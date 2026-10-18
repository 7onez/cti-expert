#!/usr/bin/env python3
"""Offline unit gate for the Webamon layer (wp_webamon + case_state + ingest_webpivot).

What it defends, each a rail that a plausible regression would break silently:
  1. keyless safety — no key: `webamon_configured()` False, every lookup None, zero network.
  2. tri-state — a vendor refusal (`skipped`) and a transport fault (`error`) propagate unmodified,
     and a 429 latches the process so later calls stop asking (no local cap; the vendor's is honoured).
  3. same_kit normaliser — the seed is excluded, per-key agreement is computed from the fingerprint
     block, and a fingerprint answering more than max_siblings hosts is boilerplate: count kept,
     siblings dropped.
  4. privacy — infostealer_exposure asks the vendor for the `domain` column only, size 1.
  5. RULE 5 frontier — same-kit siblings land in related_leads and NEVER in the seedable set,
     while a sibling that an OWNER source (narrow cert) also names still seeds.
  6. ingest — Webamon blocks become facts on the seed only; no edge is written, so
     KB.shared_indicators() can never fuse two hosts on a resold template.
Synthetic data only (*.example names, RFC 5737 addresses).
"""
import json
import os
import sys
import tempfile
import urllib.request
from contextlib import contextmanager

os.environ.setdefault("API_USAGE_LOG", os.path.join(tempfile.gettempdir(), "cti-tests-api_usage.jsonl"))

_HERE = os.path.dirname(os.path.abspath(__file__))
_ENGINE = os.path.dirname(os.path.dirname(_HERE))
for _p in (os.path.join(_ENGINE, "tools"), os.path.join(_ENGINE, "tools", "kb"),
           os.path.join(_ENGINE, "WebPivot", "tools")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import case_state as CS          # noqa: E402
import wp_webamon as W           # noqa: E402
import ingest_webpivot as IW     # noqa: E402
from knowledge_base import KB    # noqa: E402

SEED = "seed.example"
FP = {"dom_band": ["0:aaaa", "1:bbbb", "2:cccc", "3:dddd"], "dom": "d0" * 32, "links": "l1" * 32,
      "scripts": "s2" * 32, "dom_structure": "t3" * 32, "cert_config": "noise", "asn": "noise"}


@contextmanager
def patched(mod, **attrs):
    saved = {k: getattr(mod, k) for k in attrs}
    try:
        for k, v in attrs.items():
            setattr(mod, k, v)
        yield
    finally:
        for k, v in saved.items():
            setattr(mod, k, v)


@contextmanager
def no_network():
    def boom(*a, **k):
        raise AssertionError("network call attempted")
    with patched(urllib.request, urlopen=boom):
        yield


def _hit(domain, fp, title="Lure"):
    return {"resolved_domain": domain, "page_title": title, "fingerprint": fp}


def _domain_pivot(registered_on=None, **live):
    obj = {"meta": {"host": SEED},
           "pivots": [{"kind": "domain", "value": SEED, "live_results": live}]}
    if registered_on:
        obj["artifacts"] = {"whois": {"created": registered_on}}
    return obj


def _mine(obj):
    cands, deferred = {}, CS._new_deferred()
    CS._free_candidates_from_raw(obj, cands, {CS._registrable(SEED)}, deferred)
    return cands


def check():
    """Every vendor call below is mocked at the urlopen seam, but wp_webamon still ledgers it — and
    run_eval's metered-spend guard reads any ledger growth as real spend. Mocked suites must not
    ledger at all, so the client's recorder is stubbed for the whole run."""
    with patched(W, _record=lambda *a, **k: None):
        return _check()


def _check():
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    # --- 1. keyless safety ------------------------------------------------------------------
    with patched(W, webamon_key=(lambda: None), _QUOTA_HIT=False), no_network():
        ok(W.webamon_configured() is False, "keyless: webamon_configured() is False")
        for fn, args in (("domain_scans", (SEED,)), ("same_kit", (FP, SEED)), ("servers_for_domain", (SEED,)),
                         ("feed_dates", (SEED,)), ("infostealer_exposure", (SEED,)), ("plan", ())):
            try:
                r = getattr(W, fn)(*args)
                ok(r is None, f"keyless: {fn}() -> None, no network (got {r!r})")
            except AssertionError as e:
                ok(False, f"keyless: {fn}() touched the network — {e}")

    # --- 2. tri-state + 429 latch -------------------------------------------------------------
    with patched(W, webamon_key=(lambda: "FAKEKEY"), _QUOTA_HIT=False):
        with patched(W, _get=(lambda path, params=None, timeout=None: (None, {"error": "boom"}))):
            ok(W.domain_scans(SEED) == {"error": "boom"}, "tri-state: {'error'} propagates unmodified")
        with patched(W, _get=(lambda path, params=None, timeout=None: (None, {"skipped": "HTTP 403 — plan"}))):
            ok(W.same_kit(FP, SEED) == {"skipped": "HTTP 403 — plan"}, "tri-state: {'skipped'} propagates unmodified")
        with patched(W, _get=(lambda path, params=None, timeout=None: (None, {"skipped": "HTTP 403 — plan: current: starter"}))):
            ok(W.plan() == {"tier": "starter", "campaigns": False},
               "plan(): a 403 on the Pro probe reads as the plan the body names, without campaigns")

        class _Resp:
            def __init__(self, code, body):
                self.code, self._b = code, body

            def read(self):
                return json.dumps(self._b).encode()

            def close(self):
                pass

        def urlopen_429(req, timeout=None):
            raise urllib.error.HTTPError(req.full_url, 429, "Too Many", {}, _Resp(429, {"message": "quota"}))
        with patched(urllib.request, urlopen=urlopen_429):
            r = W.feed_dates(SEED)
            ok(isinstance(r, dict) and "skipped" in r and "429" in r["skipped"], f"429 -> skipped (got {r!r})")
            ok(W._QUOTA_HIT is True, "429 latches the process-wide quota flag")
        with no_network():
            r = W.servers_for_domain(SEED)
            ok(isinstance(r, dict) and "quota" in r.get("skipped", ""), "after a 429 no further call leaves the process")

    # --- 3. same_kit normaliser ---------------------------------------------------------------
    with patched(W, webamon_key=(lambda: "FAKEKEY"), _QUOTA_HIT=False):
        seen = {}
        calls = []
        cap = int(W.FINGERPRINTS["max_siblings"])

        def fake_search(lucene, index="scans", fields=None, size=None, timeout=None):
            """One response PER KEY: `scripts` is saturated boilerplate (an empty-script-list hash
            shared by the web), `dom`/`dom_band` isolate the kit, `links` widens to one template."""
            calls.append(lucene)
            seen.update(index=index, fields=fields, size=size)
            key = lucene.split("fingerprint.", 1)[1].split(":", 1)[0]
            rows = {"dom_band": ["full.example", SEED], "dom": ["full.example"],
                    "links": ["full.example", "links-only.example"], "dom_structure": ["full.example"],
                    "scripts": [f"t{i}.example" for i in range(5)]}[key]
            total = cap + 1 if key == "scripts" else len(rows)
            return ({"total_hits": total, "results": [_hit(d, {}, "Lure") for d in rows]}, None)
        with patched(W, search=fake_search):
            r = W.same_kit(FP, SEED)
        ok(len(calls) == len(W.FINGERPRINTS["same_kit"]) and all(" OR " not in c for c in calls),
           f"same_kit: ONE query per fingerprint key, never an OR ({len(calls)} calls)")
        ok(r.get("domains") == ["full.example", "links-only.example"],
           f"same_kit: seed excluded, union of non-boilerplate keys listed (got {r.get('domains')})")
        ok(r["matched"]["dom"] == ["full.example"] and r["matched"]["links"] == ["full.example", "links-only.example"],
           "same_kit: per-key agreement visible (corroboration = how many keys name a sibling)")
        ok(r["per_key"]["scripts"]["boilerplate"] is True and r["per_key"]["scripts"]["domains"] == []
           and r["per_key"]["scripts"]["total"] == cap + 1,
           "same_kit: a saturated key is boilerplate on its own — count kept, hosts dropped")
        ok(r["boilerplate"] is False and "t0.example" not in r["domains"],
           "same_kit: one saturated key does NOT drown the tight dom/dom_band match")
        ok(r["queried"]["dom_band"] == "3:dddd", "same_kit: the FINEST dom band is the one queried")
        ok(not any("cert_config" in c or "fingerprint.asn" in c for c in calls),
           "same_kit: noise fingerprints (cert_config/asn) are never queried")
        ok(all("submission_utc:[" in c for c in calls), "same_kit: every query carries the date window")
        ok("fingerprint" not in (seen["fields"] or []), "same_kit: the fingerprint block is not pulled back per hit")

        def fake_all_boiler(lucene, index="scans", fields=None, size=None, timeout=None):
            return ({"total_hits": cap + 1, "results": [_hit(f"t{i}.example", {}) for i in range(5)]}, None)
        with patched(W, search=fake_all_boiler):
            r = W.same_kit(FP, SEED)
        ok(r["boilerplate"] is True and r["domains"] == [] and r["total"] == cap + 1,
           "same_kit: every key saturated -> block is boilerplate, count kept, siblings dropped")
        ok(W.same_kit({"cert_config": "x"}, SEED).get("skipped"), "same_kit: no same-kit key on the seed -> skipped")
        import hashlib
        empty = {"links": hashlib.sha256(b"[]").hexdigest(), "scripts": hashlib.sha1(b"").hexdigest()}
        ok(W.same_kit(empty, SEED).get("skipped"), "same_kit: the hash of an EMPTY list/string is never queried as a kit")

        def fake_one_dead(lucene, index="scans", fields=None, size=None, timeout=None):
            """`scripts` 502s; every other key answers the tight kit."""
            key = lucene.split("fingerprint.", 1)[1].split(":", 1)[0]
            if key == "scripts":
                return (None, {"skipped": "HTTP 502 — Webamon search backend unavailable"})
            return ({"total_hits": 2, "results": [_hit("full.example", {}), _hit(SEED, {})]}, None)
        with patched(W, search=fake_one_dead):
            r = W.same_kit(FP, SEED)
        ok(r.get("domains") == ["full.example"] and r.get("partial") == ["scripts"]
           and "skipped" in r["per_key"]["scripts"] and "skipped" not in r,
           f"same_kit: one key's 502 is recorded on that key, the others' match survives (got {r.get('domains')}, partial={r.get('partial')})")

        # --- 4. privacy: infostealer count-only ------------------------------------------------
        def fake_stealer(lucene, index="scans", fields=None, size=None, timeout=None):
            seen.update(lucene=lucene, index=index, fields=fields, size=size)
            return ({"total_hits": 42, "results": [{"domain": "victim.example"}]}, None)
        with patched(W, search=fake_stealer):
            r = W.infostealer_exposure("victim.example")
        ok(r == {"total": 42}, f"infostealers: count only in the block (got {r!r})")
        ok(seen["index"] == "infostealers" and seen["fields"] == ["domain"] and seen["size"] == 1,
           f"infostealers: only the `domain` column, size 1, is requested (got fields={seen['fields']} size={seen['size']})")
        ok('username:"@victim.example"' in seen["lucene"], "infostealers: the mailbox clause is the QUOTED measured form")

        # --- 4b. plan(): the 403 body's `message` (not the bare `error` word) names the plan ------
        def urlopen_403(req, timeout=None):
            raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, _Resp(403, {
                "error": "Forbidden",
                "message": "Your plan does not include API access. Requires one of: mssp, research_lab, soc (current: research_lab)"}))
        with patched(urllib.request, urlopen=urlopen_403), patched(W, _QUOTA_HIT=False):
            p = W.plan()
        ok(p == {"tier": "research_lab", "campaigns": False},
           f"plan(): parses the plan out of the 403 `message`, not the `error` word (got {p!r})")

        # --- 4c. the submission gate: scan() sends NOTHING without confirm=True --------------------
        with no_network():
            b = W.scan("https://lure.example/login")
        ok(isinstance(b, dict) and b.get("submitted") is False and "confirm" in str(b.get("requires")),
           "scan(): without confirm -> offline briefing, submitted=False, zero network")
        ok(any("PUBLIC" in s for s in b.get("what_happens") or []),
           "scan(): the briefing states the scan becomes PUBLIC and permanent")
        src = open(W.__file__, encoding="utf-8").read()
        import re as _re
        ok("REQUIRES_ANALYST_CONFIRMATION" in src and _re.search(r"if not confirm:\s*\n\s*return scan_preflight\(", src),
           "scan(): the gate is MARKED and ENFORCED in source (same contract as bp_anyrun.submit)")
        # victim-bearing query strings never reach the public corpus unless the analyst says so
        victim = "https://lure.example/auth/pin?u=victim%40bank.example&token=abc#step2"
        with no_network():
            b = W.scan(victim)
        ok(b["will_submit"] == "https://lure.example/auth/pin" and b["query_stripped"] is True
           and any("STRIPPED" in s for s in b["what_happens"]),
           f"briefing: shows the exact stripped URL that would be disclosed (got {b['will_submit']})")
        ok(W.scan(victim, keep_query=True)["will_submit"] == "https://lure.example/auth/pin?u=victim%40bank.example&token=abc",
           "keep_query=True keeps the query (analyst's explicit call), still drops the fragment")
        ok(W.submission_url("lure.example")[0] == "https://lure.example" and W.submission_url("lure.example")[1] is False,
           "a bare host is submitted as https://host, nothing stripped")
        # confirmed: submit -> poll (pending, then complete) -> same_kit on the fresh scan
        calls = []

        def fake_get(path, params=None, timeout=None):
            calls.append((path, dict(params or {})))
            return ({"report_id": "r-new"}, None)
        polls = {"n": 0}

        def fake_search_scan(lucene, index="scans", fields=None, size=None, timeout=None):
            if lucene.startswith("report_id:"):
                polls["n"] += 1
                if polls["n"] == 1:
                    return ({"total_hits": 0, "results": []}, None)
                return ({"total_hits": 1, "results": [{"report_id": "r-new", "scan_status": "success",
                                                         "resolved_domain": "lure.example",
                                                         "fingerprint": {"dom": "d" * 64}}]}, None)
            return ({"total_hits": 2, "results": [_hit("twin.example", {}), _hit("lure.example", {})]}, None)
        slept = []
        with patched(W, _get=fake_get, search=fake_search_scan):
            r = W.scan("https://lure.example/login", confirm=True, wait=120, poll=30, _sleep=slept.append)
        first_polls, first_slept = polls["n"], list(slept)
        ok(calls and calls[0][0] == W.EP["scan"] and calls[0][1].get("submission_url") == "https://lure.example/login",
           "scan(confirm=True): exactly one /scan submission with the URL")
        calls.clear()
        with patched(W, _get=fake_get, search=fake_search_scan):
            polls["n"] = 5
            r2 = W.scan(victim, confirm=True, wait=0, poll=1, _sleep=slept.append)
        ok(calls[0][1].get("submission_url") == "https://lure.example/auth/pin" and r2.get("query_stripped") is True
           and r2.get("submitted_url") == "https://lure.example/auth/pin",
           "scan(confirm=True): what is actually SENT is the stripped URL, and the result says so")
        ok(r.get("submitted") is True and r.get("status") == "complete" and r["report"]["scan_status"] == "success",
           f"scan(confirm=True): polls until the report is indexed (got status={r.get('status')})")
        ok(first_slept == [30] and first_polls == 2, f"scan(): one pending poll, one sleep of `poll` s (slept={first_slept})")
        ok(r["same_kit"]["domains"] == ["twin.example"], "scan(): same-kit runs on the fresh scan's fingerprints, seed excluded")

        def never_indexed(lucene, index="scans", fields=None, size=None, timeout=None):
            return ({"total_hits": 0, "results": []}, None)
        with patched(W, _get=fake_get, search=never_indexed):
            r = W.scan("https://lure.example/login", confirm=True, wait=0, poll=30, _sleep=slept.append)
        ok(r.get("status") == "pending" and r.get("report_id") == "r-new" and "report(r-new)" in r["note"],
           "scan(): a scan not indexed within `wait` returns pending + the report_id, never re-submits")

    # --- 5. RULE 5: same-kit siblings are leads, never seeds --------------------------------
    kit = {"domains": ["kit-a.example", "kit-b.example"], "total": 3, "boilerplate": False,
           "matched": {"dom_band": ["kit-a.example", "kit-b.example"]}}
    cands = _mine(_domain_pivot(webamon_same_kit=kit))
    ok({"kit-a.example", "kit-b.example"} <= set(cands), "frontier: same-kit siblings are recorded as candidates")
    ok(all(not CS._owner_linked(v["sources"]) for v in cands.values()),
       "frontier: a same-kit-only candidate is NOT owner-linked (-> related_leads, never pending)")
    ok("webamon_same_kit" in CS._NON_OWNER_SOURCES, "case_state lists webamon_same_kit among the non-owner sources")
    # cert must postdate the seed's WHOIS registration (case_state's crt.sh date gate — see
    # test_crtsh_seed_guard.py) for the co-SAN to seed at all.
    narrow = {"certs": [{"id": 1, "issuer": "CA", "names": [SEED, "kit-a.example"],
                         "not_before": "2024-06-01T00:00:00"}], "subdomains": []}
    cands = _mine(_domain_pivot(webamon_same_kit=kit, crtsh=narrow, registered_on="2024-01-01"))
    ok(CS._owner_linked(cands["kit-a.example"]["sources"]) and not CS._owner_linked(cands["kit-b.example"]["sources"]),
       "frontier: a sibling ALSO on the seed's narrow cert seeds; the kit-only one stays a lead")
    boiler = {"domains": [], "total": 900, "boilerplate": True}
    ok(not _mine(_domain_pivot(webamon_same_kit=boiler)), "frontier: a boilerplate block contributes no candidate")

    # --- 6. ingest: facts only, no edges ------------------------------------------------------
    raw = _domain_pivot(
        webamon={"report_id": "r1", "risk_score": 13, "page_title": "Sign in", "fingerprint": FP, "total": 1},
        webamon_same_kit=kit, webamon_feeds={"registered": "20260915", "removed": None},
        webamon_infostealers={"total": 0},
        webamon_servers={"total": 1, "servers": [{"ip": "203.0.113.5", "asn": 64496, "first_seen": "2026-09-01T00:00:00Z",
                                                   "last_seen": "2026-09-02T00:00:00Z"}]})
    raw["artifacts"] = {}
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "seed.example.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(raw, fh)
        kb = KB(os.path.join(td, "kb"))
        IW.ingest_file(kb, p)
        ent = kb.entity("domain", SEED)
        attrs = {f["attribute"]: f["value"] for f in ent.get("facts") or []}
        ok(attrs.get("webamon_risk_score") == "13" and attrs.get("webamon_feed_registered") == "20260915",
           "ingest: risk score + NRD feed day recorded as facts on the seed")
        ok(attrs.get("webamon_fingerprint_dom_band") == "3:dddd", "ingest: the finest dom band is the fingerprint fact")
        sibs = [f["value"] for f in ent["facts"] if f["attribute"] == "webamon_same_kit_sibling"]
        ok(len(sibs) == 2 and all(" (dom_band)" in s for s in sibs), f"ingest: siblings are facts naming the agreeing keys (got {sibs})")
        webamon_edges = [e for e in kb._edges if e.get("source") == "webamon" or "webamon" in json.dumps(e)]
        ok(not webamon_edges, "ingest: NO edge is written for any Webamon block (siblings cannot cluster)")
        ok(not os.path.exists(kb._ent_file("domain", "kit-a.example")) or not kb.entity("domain", "kit-a.example")["facts"],
           "ingest: a same-kit sibling gets no entity/facts of its own")
        ok(attrs.get("webamon_infostealer_rows") == "0" and attrs.get("webamon_hosting_ip", "").startswith("203.0.113.5 AS64496"),
           "ingest: infostealer count + hosting era are facts")

    return passed, failed, out


def main():
    passed, failed, lines = check()
    for status, label in lines:
        print(f"[{status}] {label}")
    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
