#!/usr/bin/env python3
"""
test_misp.py — the gate on the MISP dissemination layer (IntelShare).

Run:  python3 tests/test_misp.py
      python3 tools/eval/run_eval.py          (runs as part of the regression gate)

WHAT THIS PROTECTS
------------------
This is the only layer whose mistakes leave the building. A wrong cluster makes our assessment
wrong; a wrong indicator, published, makes every subscriber's blocklist wrong. Four properties
therefore have to hold in CODE, not in a docstring, and each has a silent failure mode:

  1. NOTHING LEAVES WITHOUT A HUMAN. Both mutating entry points return a briefing and send
     nothing unless confirmation is present, and `publish` additionally requires the environment
     lock an agent cannot set for itself. A gate that quietly stopped firing would look exactly
     like a gate that was never reached.
  2. PUSH IS NOT PUBLISH. The staging clamp is applied in code: whatever distribution the export
     requested, a push produces an organisation-only, unpublished event. If the clamp broke, a
     routine "stage this" would silently become community-wide sharing.
  3. OWNERSHIP AND BASE RATES ARE REFUSALS, NOT WARNINGS. A victim host's own artifacts, a
     benign-check result, a parking favicon, a CDN hostname and a malformed value never reach an
     event. Every one of those failures produces a plausible-looking event, which is why they
     must be asserted rather than eyeballed.
  4. PERSONAL DATA IS APPROVED PER VALUE. Registrant names, emails, phones and identity handles
     are held back and released one value at a time. A blanket release path that also caught PII
     is how a case's personal data reaches a sync partner by accident.

Everything here is offline: no MISP instance, no network, no credentials, and the case fixtures
are synthetic placeholders (RULE 1 — no case data in a tracked file).
"""
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "IntelShare", "tools"), os.path.join(ROOT, "tools", "kb")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import sh_export as X          # noqa: E402
import sh_misp as M            # noqa: E402


# ------------------------------------------------------------------ synthetic case fixtures
def _all_attributes(result):
    """Every attribute in the event, loose OR inside an object. A value folded into a `whois`
    object is still in the event — asserting only against the loose list would read a structural
    improvement as a lost indicator."""
    ev = result["Event"]
    out = list(ev.get("Attribute") or [])
    for o in ev.get("Object") or []:
        out += list(o.get("Attribute") or [])
    return out


def _pivot(kind, value, confidence="high"):
    return {"kind": kind, "value": value, "confidence": confidence}


def _write_case(root, case, pivots, *, target_class="confirmed_scam", host="site-a.example"):
    raw = os.path.join(root, "cases", case, "raw")
    os.makedirs(raw, exist_ok=True)
    with open(os.path.join(raw, f"{host}.json"), "w", encoding="utf-8") as fh:
        json.dump({"meta": {"host": host, "source": f"https://{host}",
                            "collected_at": "2026-01-02T03:04:05Z"},
                   "artifacts": {}, "pivots": pivots}, fh)
    if target_class:
        with open(os.path.join(root, "cases", case, "scope.json"), "w", encoding="utf-8") as fh:
            json.dump({"target_class": target_class, "case": case}, fh)


_PARKING_FAVICON = None
try:
    import noise_filters as _NF
    _PARKING_FAVICON = sorted(_NF.PARKING_FAVICON_MMH3)[0] if _NF.PARKING_FAVICON_MMH3 else None
except Exception:  # noqa: BLE001
    _NF = None


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

    # HERMETIC: neutralise any real instance for the duration. Without this the module is not a
    # unit test at all on a machine that has MISP configured — `publish` fetches the event to
    # build its briefing and `push --dry-run` validates types against describeTypes, so the
    # regression gate quietly starts making outbound calls to somebody's production server. The
    # eval's metered-spend guard is what caught it; the fix belongs here, not in the guard.
    _saved_env = {k: os.environ.pop(k, None)
                  for k in ("MISP_URL", "MISP_BASE_URL", "MISP_KEY", "MISP_API_KEY",
                            "MISP_AUTHKEY")}
    tmp = tempfile.mkdtemp(prefix="misp_test_")
    try:
        ok(not M.misp_configured(),
           "the test runs against NO instance — a unit gate must never touch a live MISP")
        # --- 1. a normal case: what is shared, held and refused ---------------------------
        pivots = [
            _pivot("domain", "site-a.example"),
            _pivot("domain", "site-b.example"),
            _pivot("file:sha256", "a" * 64),
            _pivot("favicon_hash", 123456789),
            _pivot("jarm:hash", "2" * 62),
            _pivot("whois:registrant_email", "registrant@example.com"),
            _pivot("whois:registrant_name", "Registrant Name"),
            _pivot("phone", "+1 555 0100"),
            _pivot("social:telegram", "operator_a"),
            _pivot("third_party_host", "cdn.example.net"),
            _pivot("robots_disallow", "/admin"),
            _pivot("file:sha256", "b" * 12),                     # truncated — malformed
            _pivot("totally_unmapped_kind", "whatever"),
        ]
        _write_case(tmp, "c1", pivots)
        r = X.build_event("c1", root=tmp)
        vals = {a["value"] for a in r["Event"]["Attribute"]}
        types = {a["value"]: a["type"] for a in r["Event"]["Attribute"]}
        rev = {str(x["value"]) for x in r["review"]}
        exc = {str(x["value"]): x["reason"] for x in r["excluded"]}

        ok("site-a.example" in vals and types.get("site-a.example") == "domain",
           "a two-label domain is shared as `domain` (the validator must not demand three labels "
           "— the regression that silently dropped every apex from an event)")
        ok("a" * 64 in vals, "a well-formed sha256 is shared")
        ok(str(123456789) in vals, "a favicon hash is shared as a hunting pivot")

        ok("registrant@example.com" in rev and "registrant@example.com" not in vals,
           "a registrant EMAIL is held for review, not shared")
        ok("Registrant Name" in rev and "+1 555 0100" in rev,
           "a registrant NAME and a phone number are held for review")
        ok("operator_a" in rev, "an identity handle is held for review")

        ok("cdn.example.net" in exc and "cdn" not in vals,
           "a third_party_host is REFUSED as a class — it is a CDN/SaaS name by construction")
        ok("/admin" in exc, "page context (a robots.txt rule) is refused")
        ok("b" * 12 in exc and "shape" in exc.get("b" * 12, ""),
           "a truncated hash is refused — an indicator that cannot match anything is noise in "
           "somebody else's feed")
        ok("whatever" in exc and "no MISP mapping" in exc.get("whatever", ""),
           "an unmapped pivot kind is refused AND NAMED, never guessed at")

        # --- 2. to_ids discipline ---------------------------------------------------------
        ids = {a["value"]: a["to_ids"] for a in r["Event"]["Attribute"]}
        ok(ids.get("site-a.example") is True, "a domain carries to_ids — it is detectable")
        ok(ids.get(str(123456789)) is False and ids.get("2" * 62) is False,
           "a favicon hash and a JARM never carry to_ids: they are for FINDING more, not for "
           "blocking (thousands of unrelated hosts share them)")
        ok(all(a.get("distribution") == 5 for a in r["Event"]["Attribute"]),
           "every attribute inherits the event's distribution, so no attribute can be more "
           "widely visible than the event it sits in")

        # --- 3. personal data is released PER VALUE, not in bulk ---------------------------
        r2 = X.build_event("c1", root=tmp, review_values=["registrant@example.com"])
        v2 = {a["value"] for a in _all_attributes(r2)}
        ok("registrant@example.com" in v2, "an explicitly approved value is included")
        ok("Registrant Name" not in v2 and "+1 555 0100" not in v2,
           "approving ONE value releases only that value — the other personal data stays held")
        r3 = X.build_event("c1", root=tmp, include_review=True)
        ok("Registrant Name" in {a["value"] for a in _all_attributes(r3)},
           "include_review is the blanket release, and is a separate, deliberate choice")

        # --- 3b. MISP OBJECTS and the EVENT REPORT (standards compliance) ------------------
        whois_objs = [o for o in (r3["Event"].get("Object") or []) if o["name"] == "whois"]
        ok(whois_objs,
           "released WHOIS values are folded into a `whois` OBJECT — four loose attributes say "
           "four values appeared somewhere in the case; the object says THIS domain's "
           "registration record named them, which is what a receiver can reason about")
        if whois_objs:
            o = whois_objs[0]
            rels = [a.get("object_relation") for a in o["Attribute"]]
            ok(o.get("template_uuid") and o.get("meta-category"),
               "an object carries its template uuid and meta-category, or MISP cannot bind it "
               "to a template")
            ok("domain" in rels,
               "the object is ANCHORED to the host it describes, which is what makes it a record "
               "rather than a bag of fields")
            repeatable = set((X.OBJECTS.get("whois") or {}).get("multiple_relations") or [])
            dupes = [x for x in set(rels) if rels.count(x) > 1 and x not in repeatable]
            ok(not dupes,
               "no object_relation repeats unless its template marks it `multiple` — two "
               "registrant emails on one whois object assert a single record named both"
               + (f" (found {dupes})" if dupes else ""))
        singles = X.build_event("c1", root=tmp)          # hashes with nothing else known
        ok(not [o for o in (singles["Event"].get("Object") or []) if o["name"] == "file"],
           "a lone file hash stays a plain attribute — an object exists to GROUP, and twenty "
           "one-attribute `file` objects are noise dressed as structure")

        rep = (r3.get("EventReport") or [{}])[0]
        content = rep.get("content") or ""
        ok(rep.get("name") and content, "the export carries an event report")
        ok("TLP" in content and "to_ids" in content,
           "the report states the handling rule and what to_ids means for a receiver")
        ok("NOT included" in content or "not included" in content.lower(),
           "the report tells the receiver what was deliberately withheld — an indicator list "
           "with no such statement reads as complete")
        ok(all(a.get("first_seen") for a in _all_attributes(r3) if a.get("value")),
           "every attribute is dated, so a receiver can age it out rather than trusting it "
           "indefinitely")
        ok(r3["Event"]["date"] == "2026-01-02",
           "the event date is the OBSERVATION date, not the export date — stamping today on a "
           "three-week-old collection makes stale infrastructure look fresh")

        # --- 4. ownership: the intake class decides shareability first ---------------------
        _write_case(tmp, "c_victim", pivots, target_class="victim_host", host="victim.example")
        rv = X.build_event("c_victim", root=tmp, include_review=True)
        ok(rv["counts"]["attributes"] == 0 and rv["meta"].get("refusal"),
           "a victim_host case is REFUSED even with the blanket release — a compromised site's "
           "WHOIS/favicon/certificate belong to the victim, and publishing them points other "
           "people's detections at a victim")
        _write_case(tmp, "c_benign", pivots, target_class="benign_check", host="legit.example")
        rb = X.build_event("c_benign", root=tmp, include_review=True)
        ok(rb["counts"]["attributes"] == 0 and rb["meta"].get("refusal"),
           "a benign_check case is REFUSED — an event naming a legitimate site is defamatory and "
           "un-recallable once it syncs")
        _write_case(tmp, "c_susp", pivots, target_class="suspected_scam", host="site-c.example")
        rs = X.build_event("c_susp", root=tmp)
        ok(rs["counts"]["attributes"] > 0 and rs["meta"]["requires_acknowledgement"],
           "a suspected_scam case is shareable WITH an acknowledgement, not capped to nothing — "
           "capping it would only train the analyst to wave everything through with the one flag "
           "that also releases personal data")
        ok(any("workflow" in t["name"] for t in rs["Event"]["Tag"]),
           "the caveat travels into the event as a workflow tag, so the receiving analyst holds "
           "the same reservation we do")

        # --- 5. base-rate refusals ---------------------------------------------------------
        if _PARKING_FAVICON is not None:
            _write_case(tmp, "c_park", [_pivot("favicon_hash", _PARKING_FAVICON),
                                        _pivot("domain", "site-d.example")],
                        host="site-d.example")
            rp = X.build_event("c_park", root=tmp)
            ok(str(_PARKING_FAVICON) not in {a["value"] for a in rp["Event"]["Attribute"]},
               "a parking/template favicon is refused — it matches half a hosting provider's "
               "estate, so shared as an indicator it is a false positive generator")
        else:
            ok(False, "the KB parking-favicon list is readable (needed for the base-rate check)")

        # --- 6. our own operational strings never leave -------------------------------------
        rl = X.build_event("c1", root=tmp, info="CASE-0001 — writeup")
        ok(rl["counts"]["attributes"] == 0 and "REFUSED" in str(rl["meta"].get("refusal")),
           "an event headline carrying a case identifier REFUSES the export rather than being "
           "silently stripped — a quiet strip hides that the value was in scope at all")

        # --- 7. truncation is loud ----------------------------------------------------------
        rt = X.build_event("c1", root=tmp, max_attributes=2)
        ok(rt["counts"]["attributes"] == 2
           and any("TRUNCAT" in w.upper() for w in rt["meta"]["warnings"]),
           "a truncated attribute list says so — a shortened event is otherwise indistinguishable "
           "from a case that found less")

        # --- 8. THE GATES: nothing leaves without a human -----------------------------------
        export = X.build_event("c1", root=tmp, requested_distribution=3)
        b = M.push(export)
        ok(str(b.get("action", "")).startswith("CONFIRMATION REQUIRED") and not b.get("sent"),
           "push WITHOUT confirmation returns the briefing and sends nothing")
        ok(b.get("attributes", {}).get("total") == export["counts"]["attributes"]
           and "to_ids" in b.get("attributes", {}),
           "the briefing states the attribute count and how many become blocking rules")
        ok("intake_class" in b and "held_back" in b,
           "the briefing carries the case's intake class and what was held back")

        d = M.push(export, confirm=True, dry_run=True)
        body = ((d.get("request") or {}).get("body") or {}).get("Event") or {}
        ok(d.get("sent") is False, "a dry-run push sends nothing")
        ok(body.get("distribution") == 0 and body.get("published") is False,
           "THE STAGING CLAMP: an export requesting distribution 3 is still pushed as "
           "organisation-only and unpublished — push is not publish")

        lock = str(X.POLICY.get("publish_env_lock") or "INTEL_MISP_PUBLISH")
        saved = os.environ.pop(lock, None)
        try:
            p1 = M.publish("1", distribution=3)
            ok(str(p1.get("action", "")).startswith("CONFIRMATION REQUIRED")
               and p1.get("irreversible") is True,
               "publish WITHOUT confirmation returns the briefing, states the audience and that "
               "it cannot be undone, and sends nothing")
            ok(p1["requested_distribution"]["recallable"] is False,
               "the briefing says plainly that the requested level is not recallable")
            p2 = M.publish("1", distribution=3, confirm=True)
            ok(not p2.get("sent") and "blocked_by" in p2,
               "confirmation alone is NOT enough: without the environment lock the tool says so "
               "and still sends nothing — the lock is a human's act, not an agent's")
            os.environ[lock] = "1"
            p3 = M.publish("1", distribution=4, confirm=True)
            ok(p3.get("sent") is False and "sharing_group_id" in str(p3.get("error", "")),
               "distribution 4 without a sharing group is refused — neither MISP nor the analyst "
               "would know the real audience")
        finally:
            os.environ.pop(lock, None)
            if saved is not None:
                os.environ[lock] = saved

        # --- 9. type validation degrades, never fails the push ------------------------------
        M._TYPES_CACHE = {"types": ["domain", "text"], "categories": []}
        ev, notes = M.validate_event({"Attribute": [{"type": "eth", "value": "0x" + "1" * 40,
                                                     "comment": ""},
                                                    {"type": "domain", "value": "site-a.example"}]})
        M._TYPES_CACHE = {}
        ok(ev["Attribute"][0]["type"] == "text" and ev["Attribute"][1]["type"] == "domain",
           "an attribute type the instance does not know is DOWNGRADED to text, so the value is "
           "still stored and still correlates instead of failing the whole push")
        ok(notes and "intended type" in ev["Attribute"][0]["comment"],
           "the downgrade is recorded in the attribute and reported, not silent")

        # --- 10. an empty / missing case is absence of COLLECTION ---------------------------
        re_ = X.build_event("no_such_case", root=tmp)
        ok(re_["counts"]["attributes"] == 0
           and any("absence of COLLECTION" in w for w in re_["meta"]["warnings"]),
           "a case with nothing collected is reported as absence of COLLECTION, never as a case "
           "with no indicators")
        pe = M.push(re_)
        ok(not pe.get("ok") and not pe.get("sent"),
           "an event with no attributes is not pushed")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        for _k, _v in _saved_env.items():
            if _v is not None:
                os.environ[_k] = _v

    return passed, failed, out


if __name__ == "__main__":
    _PASSED, _FAILED, _LINES = check()
    for _status, _label in _LINES:
        print(f"  {'ok  ' if _status == 'ok' else 'FAIL'} {_label}")
    print(f"\n{'PASS' if not _FAILED else 'FAIL'} — {_PASSED} passed, {_FAILED} failed")
    sys.exit(1 if _FAILED else 0)
