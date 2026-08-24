#!/usr/bin/env python3
"""sh_misp.py — the MISP instance client: the only file in this skill that sends anything.

THE TWO-STEP RAIL
-----------------
Sharing is not one action, it is two, and collapsing them is how indicators escape by accident:

    PUSH      creates or updates the event ON YOUR OWN INSTANCE, always at distribution 0
              (your organisation only) and always `published: false`. Nobody outside your
              organisation can see it, no sync has happened, and you can delete it. This step
              needs the analyst's yes (`--confirm-push`) and nothing else.

    PUBLISH   raises the distribution and flips `published`. THAT is the irreversible one: MISP
              pushes the event to every server this instance synchronises with and notifies
              subscribers. Deleting your copy afterwards deletes nothing of theirs. This step
              needs the analyst's yes AND the environment lock `INTEL_MISP_PUBLISH=1`, which an
              agent loop cannot set for itself.

The staging clamp is enforced here, in code, from `references/misp.json` — a caller that asks
`push` for distribution 3 gets an organisation-only event and is told so. The only way to widen
the audience is the second step, and the second step asks a human.

WITHOUT CONFIRMATION, EVERY MUTATING ENTRY POINT RETURNS A BRIEFING AND SENDS NOTHING
-------------------------------------------------------------------------------------
The briefing is the point: it states the instance, the exact audience, the attribute counts by
type, how many carry `to_ids` (i.e. how many will end up in somebody's blocklist), which values
are personal data, and what cannot be undone. Show it to the analyst; do not summarise it away.

READ-ONLY BY DEFAULT
--------------------
`keycheck` and `search` send nothing of the case: `search` asks whether an indicator is ALREADY
known to the instance, which is the single most useful call to make before deciding to publish —
a value your community already has does not need re-sharing, and a value nobody has is the one
worth the trouble. Both are safe to call unattended.

CLI
---
    sh_misp.py keycheck                                  # configured? reachable? which version?
    sh_misp.py search <value> [--type domain]            # already known here?
    sh_misp.py push  <event.json>                        # briefing only — sends NOTHING
    sh_misp.py push  <event.json> --confirm-push         # stage: org-only, unpublished
    sh_misp.py publish <event-id>                        # briefing only — sends NOTHING
    sh_misp.py publish <event-id> --distribution 1 --confirm-publish   # + INTEL_MISP_PUBLISH=1
    sh_misp.py budget                                    # offline: requests used this run

Python 3 stdlib only.
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

from sh_export import (BUDGET, ENDPOINTS, POLICY, REPORTING,
                       _dist_entry, _repo_root, _utcnow, leak_scan)

try:                                    # the licensed-API ledger, when the full repo is present
    sys.path.append(os.path.join(_repo_root(), "WebPivot", "tools"))
    import api_usage                    # noqa: E402
except Exception:                       # noqa: BLE001
    api_usage = None

USER_AGENT = "IntelShare/1.0 (+MISP API client)"

_REQUESTS_THIS_RUN = 0


# --------------------------------------------------------------------------- config
def _load_env_file(path: str) -> None:
    """Populate os.environ from a KEY=VALUE .env, never overriding a real environment variable."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k and k not in os.environ:
                    os.environ[k] = v
    except Exception:  # noqa: BLE001
        pass


for _cand in (os.path.join(os.getcwd(), ".env"), os.path.join(_repo_root(), ".env")):
    _load_env_file(_cand)


def _secret(*names):
    for n in names:
        v = os.environ.get(n)
        if v and v.strip():
            return v.strip()
    return None


def base_url() -> str:
    return (_secret("MISP_URL", "MISP_BASE_URL") or "").rstrip("/")


def api_key() -> str:
    return _secret("MISP_KEY", "MISP_API_KEY", "MISP_AUTHKEY") or ""


def misp_configured() -> bool:
    return bool(base_url() and api_key())


def _verify_tls() -> bool:
    """Self-hosted instances often carry a private CA. Disabling verification is allowed, loudly:
    an unverified TLS session to the instance that holds your case material is a real exposure."""
    v = (os.environ.get("MISP_VERIFY_TLS") or "").strip().lower()
    if v in ("0", "false", "no", "off"):
        print("[misp] WARNING: TLS verification DISABLED (MISP_VERIFY_TLS=0). The connection to "
              "the instance is not authenticated.", file=sys.stderr)
        return False
    return True


def _org_label() -> str:
    return os.environ.get("MISP_ORG") or "(your organisation)"


# --------------------------------------------------------------------------- transport
def _budget_block() -> str:
    cap = int(BUDGET.get("max_requests_per_run", 40))
    if _REQUESTS_THIS_RUN >= cap:
        return f"per-run MISP request cap reached ({_REQUESTS_THIS_RUN}/{cap})"
    return ""


def _request(method: str, path: str, payload=None, *, timeout: int = 0) -> dict:
    """One REST call. Returns {"ok", "status", "data"|"error"} and never raises — a failed share
    must report why, not kill the case."""
    global _REQUESTS_THIS_RUN
    if not misp_configured():
        return {"ok": False, "status": 0, "error": REPORTING.get("not_configured")}
    blocked = _budget_block()
    if blocked:
        return {"ok": False, "status": 0, "error": blocked}
    url = base_url() + path
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=body, method=method.upper())
    req.add_header("Authorization", api_key())
    req.add_header("Accept", "application/json")
    req.add_header("Content-Type", "application/json")
    # A self-hosted MISP commonly sits behind Cloudflare, whose default bot rules reject a client
    # that sends no User-Agent (urllib sends `Python-urllib/3.x`). The refusal arrives as a plain
    # 403 — indistinguishable from a rejected API key unless you read the body — so we always
    # identify ourselves. Any explicit UA satisfies the rule; this one is honest about what we
    # are, and MISP_USER_AGENT overrides it for an instance with a stricter allowlist.
    req.add_header("User-Agent", os.environ.get("MISP_USER_AGENT") or USER_AGENT)
    ctx = None if _verify_tls() else ssl._create_unverified_context()  # noqa: SLF001
    _REQUESTS_THIS_RUN += 1
    status, raw, err = 0, "", ""
    try:
        with urllib.request.urlopen(req, timeout=timeout or int(
                BUDGET.get("http_timeout_seconds", 45)), context=ctx) as resp:
            status = resp.getcode()
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status = e.code
        raw = e.read().decode("utf-8", "replace") if hasattr(e, "read") else ""
        err = f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        err = f"{type(e).__name__}: {e}"
    if api_usage is not None:
        try:
            api_usage.record("misp", path.split("/")[1] if "/" in path else path,
                             credits=0, query=path, ok=(200 <= status < 300))
        except Exception:  # noqa: BLE001
            pass
    try:
        data = json.loads(raw) if raw else {}
    except Exception:  # noqa: BLE001
        data = {"raw": raw[:2000]}
    if 200 <= status < 300:
        return {"ok": True, "status": status, "data": data}
    detail = ""
    if isinstance(data, dict):
        detail = str(data.get("message") or data.get("errors") or data.get("title") or "")[:300]
    blob = (raw or "") + str(detail)
    if status == 403 and ("cloudflare" in blob.lower() or "1010" in blob):
        detail = ("blocked by the WAF IN FRONT of MISP (Cloudflare), not by MISP — this is a "
                  "CHANNEL refusal and says nothing about your API key. Set MISP_USER_AGENT, or "
                  "allowlist this client at the WAF.")
    elif status in (401, 403):
        detail = detail or ("MISP rejected the credential — check the auth key is enabled and "
                            "that its role may use the API.")
    return {"ok": False, "status": status, "error": (err or f"HTTP {status}") + (
        f" — {detail}" if detail else ""), "data": data}


def budget_status() -> dict:
    cap = int(BUDGET.get("max_requests_per_run", 40))
    return {"requests_this_run": _REQUESTS_THIS_RUN, "max_requests_per_run": cap,
            "remaining_this_run": max(0, cap - _REQUESTS_THIS_RUN),
            "note": "A self-hosted MISP costs nothing per call; this cap bounds blast radius, "
                    "not spend."}


# --------------------------------------------------------------------------- read-only calls
def keycheck() -> dict:
    """Is the channel configured, reachable and authenticated? Sends no case data."""
    out = {"configured": misp_configured(), "url": base_url() or None,
           "key_present": bool(api_key()), "verify_tls": _verify_tls()}
    if not out["configured"]:
        out["note"] = REPORTING.get("not_configured")
        out["how"] = ("export MISP_URL=https://misp.your-org.example and MISP_KEY=<your API key> "
                      "(Administration → List Auth Keys in the MISP UI), or put them in the "
                      "repo-root .env.")
        return out
    r = _request("GET", ENDPOINTS.get("version", "/servers/getVersion"))
    out["reachable"] = r["ok"]
    if r["ok"]:
        out["version"] = (r["data"] or {}).get("version")
        types = describe_types()
        out["known_attribute_types"] = len(types.get("types") or [])
    else:
        out["error"] = r.get("error")
        out["note"] = ("The instance did not answer. This is a CHANNEL failure — it says nothing "
                       "about whether the indicators are worth sharing.")
    return out


_TYPES_CACHE: dict = {}


def describe_types() -> dict:
    """The instance's own list of valid attribute types/categories. Cached per process. This is
    what makes the mapping table safe across MISP versions: a type this deployment does not know
    is downgraded, not guessed."""
    global _TYPES_CACHE
    if _TYPES_CACHE:
        return _TYPES_CACHE
    r = _request("GET", ENDPOINTS.get("describe_types", "/attributes/describeTypes.json"))
    if not r["ok"]:
        _TYPES_CACHE = {"types": [], "categories": [], "error": r.get("error")}
        return _TYPES_CACHE
    result = ((r["data"] or {}).get("result") or {})
    _TYPES_CACHE = {"types": list(result.get("types") or []),
                    "categories": list(result.get("categories") or [])}
    return _TYPES_CACHE


def search(value: str, *, type_: str = "", limit: int = 25) -> dict:
    """Is this indicator ALREADY known to the instance? Read-only, and the right call to make
    before deciding whether publishing adds anything."""
    if not misp_configured():
        return {"configured": False, "note": REPORTING.get("not_configured")}
    payload = {"returnFormat": "json", "value": str(value), "limit": int(limit)}
    if type_:
        payload["type"] = type_
    r = _request("POST", ENDPOINTS.get("search_attributes", "/attributes/restSearch"), payload)
    if not r["ok"]:
        return {"configured": True, "ok": False, "error": r.get("error"),
                "note": "Query failed — absence of an ANSWER, not evidence the value is unknown."}
    attrs = (((r["data"] or {}).get("response") or {}).get("Attribute") or [])
    return {
        "configured": True, "ok": True, "value": value, "matches": len(attrs),
        "events": sorted({str(a.get("event_id")) for a in attrs})[:20],
        "attributes": [{"type": a.get("type"), "category": a.get("category"),
                        "to_ids": a.get("to_ids"), "event_id": a.get("event_id"),
                        "comment": str(a.get("comment") or "")[:120]} for a in attrs[:limit]],
        "note": ("Already present on this instance — re-sharing adds nothing but noise; consider "
                 "extending the existing event instead." if attrs else
                 "Not known to this instance. Absence here is absence on THIS instance only."),
    }


# --------------------------------------------------------------------------- validation
def validate_event(event: dict) -> tuple:
    """(event, notes). Downgrade any attribute type the instance does not know to `text`, so the
    value is still stored and still correlates, and say so — an unknown type is otherwise a
    silent rejection of the whole push."""
    types = describe_types()
    known = set(types.get("types") or [])
    notes = []
    if not known:
        notes.append("could not read the instance's attribute-type list; types were not validated"
                     + (f" ({types.get('error')})" if types.get("error") else ""))
        return event, notes
    ev = json.loads(json.dumps(event))          # never mutate the caller's event in place
    for a in ev.get("Attribute") or []:
        if a.get("type") not in known:
            notes.append(f"{a.get('type')} → text  ({REPORTING.get('type_downgraded')})")
            a["comment"] = (a.get("comment") or "") + f" [intended type: {a.get('type')}]"
            a["type"] = "text"
    return ev, notes


# --------------------------------------------------------------------------- the gated writes
def _load_export(source) -> dict:
    if isinstance(source, dict):
        return source
    with open(str(source), encoding="utf-8") as fh:
        return json.load(fh)


def _event_of(export: dict) -> dict:
    return export.get("Event") if isinstance(export.get("Event"), dict) else export


def _attr_summary(event: dict) -> dict:
    by_type, ids = {}, 0
    for a in event.get("Attribute") or []:
        by_type[a.get("type")] = by_type.get(a.get("type"), 0) + 1
        if a.get("to_ids"):
            ids += 1
    return {"total": len(event.get("Attribute") or []), "by_type": by_type, "to_ids": ids}


def push_briefing(export: dict, *, event_id=None) -> dict:
    """What a push would do. Returned INSTEAD of acting when confirmation is absent."""
    event = _event_of(export)
    meta = export.get("meta") or {}
    staged = int(POLICY.get("staging_distribution", 0))
    summary = _attr_summary(event)
    return {
        "action": "CONFIRMATION REQUIRED — nothing has been sent to MISP",
        "instance": base_url() or "(not configured)",
        "organisation": _org_label(),
        "event": {"info": event.get("info"), "date": event.get("date"),
                  "threat_level_id": event.get("threat_level_id"),
                  "analysis": event.get("analysis"),
                  "tags": [t.get("name") for t in (event.get("Tag") or [])]},
        "mode": f"UPDATE event {event_id}" if event_id else "CREATE a new event",
        "attributes": summary,
        "to_ids_meaning": (f"{summary['to_ids']} attribute(s) are marked to_ids — a subscriber's "
                           f"detection stack may BLOCK on those values. Everything else is a "
                           f"hunting pivot and will not be blocked on."),
        "staged_as": (f"distribution {staged} "
                      f"({_dist_entry(staged).get('name')}), published=false"),
        "audience_now": _dist_entry(staged).get("who"),
        "reversible": ("Yes. An unpublished organisation-only event has reached nobody and can "
                       "be deleted from the instance."),
        "objects": [{"name": o.get("name"), "values": len(o.get("Attribute") or [])}
                    for o in (event.get("Object") or [])],
        "event_report": [{"name": r.get("name"), "chars": len(str(r.get("content") or ""))}
                         for r in (export.get("EventReport") or [])],
        "held_back": {"review": len(export.get("review") or []),
                      "excluded": len(export.get("excluded") or [])},
        "intake_class": meta.get("target_class"),
        "acknowledge_before_sharing": (meta.get("class_note") or "")
        if meta.get("requires_acknowledgement") else "",
        "case_warnings": meta.get("warnings") or [],
        "will_not": [
            "raise the distribution above the staging level",
            "publish the event or notify anybody",
            "include the values held for review",
        ],
        "to_proceed": ("Show this to the analyst, ask whether to stage it on MISP, and only then "
                       "call push(..., confirm=True) — CLI: sh_misp.py push <file> "
                       "--confirm-push."),
    }


def existing_event(event_id) -> dict:
    """What the event already holds — its object keys and its reports by name.

    UPDATING AN EVENT IS NOT IDEMPOTENT IN MISP, and finding that out in production is expensive:
    `/events/edit` de-duplicates ATTRIBUTES by value but APPENDS objects, and the event-report
    endpoint always creates a new report. Re-pushing a case therefore doubles its objects and
    leaves two copies of the narrative — an event that reads as though the same registration
    record were found twice. So an update reads first."""
    if not event_id:
        return {"objects": set(), "reports": {}}
    r = _request("GET", ENDPOINTS.get("get_event", "/events/view/{event_id}").format(
        event_id=event_id))
    ev = ((r.get("data") or {}).get("Event") or {}) if r["ok"] else {}
    keys = set()
    for o in ev.get("Object") or []:
        vals = sorted(str(a.get("value")) for a in (o.get("Attribute") or []))
        keys.add((str(o.get("name")), "|".join(vals)))
    reports = {str(rep.get("name")): rep.get("id") for rep in (ev.get("EventReport") or [])
               if not rep.get("deleted")}
    return {"objects": keys, "reports": reports}


def put_event_report(event_id, report: dict, existing_reports: dict | None = None) -> dict:
    """Attach the markdown EVENT REPORT — the narrative MISP renders above the attributes —
    replacing the one of the same name if it is already there.

    It goes through its own endpoint by design: a report key inside the event body is dropped
    silently, which would ship the indicators with their caveats quietly missing."""
    name = str(report.get("name") or "Report")
    body = {"EventReport": {"name": name, "content": str(report.get("content") or ""),
                            "distribution": 5}}
    existing_id = (existing_reports or {}).get(name)
    if existing_id:
        path = ENDPOINTS.get("edit_event_report", "/eventReports/edit/{report_id}").format(
            report_id=existing_id)
        out = _request("POST", path, body)
        if out["ok"]:
            out["replaced"] = True
            return out
    path = ENDPOINTS.get("add_event_report", "/eventReports/add/{event_id}").format(
        event_id=event_id)
    return _request("POST", path, body)


def push(source, *, confirm: bool = False, event_id=None, case: str = "",
         dry_run: bool = False, publish: bool = False, distribution: int = 0) -> dict:
    """Create or update the event on the instance. ALWAYS stages first: organisation-only and
    unpublished, whatever distribution the export requested.

    `publish=True` runs the sharing step immediately afterwards, for the analyst who has decided
    both questions at once. It is NOT a way around the gate: the publish step re-checks its own
    confirmation and the environment lock, so without the lock the event stays staged and the
    result says exactly that. Staging and sharing remain two acts — this only lets one command
    perform both when a human has authorised both."""
    export = _load_export(source)
    event = dict(_event_of(export))
    meta = export.get("meta") or {}
    case = case or str(meta.get("case") or "")

    if meta.get("refusal"):
        return {"ok": False, "sent": False, "refused": meta["refusal"],
                "note": "The export refused itself; nothing to push."}
    if not event.get("Attribute"):
        return {"ok": False, "sent": False,
                "note": "The event carries no attributes — nothing to share. Check the export's "
                        "`review`/`excluded` lists before reading this as 'the case found "
                        "nothing'."}
    leaks = leak_scan(event.get("info"))
    if leaks:
        return {"ok": False, "sent": False,
                "refused": f"the event info carries our own operational strings {leaks}"}
    if not confirm:
        return push_briefing(export, event_id=event_id)

    # The staging clamp: enforced here, not trusted from the caller.
    event["distribution"] = int(POLICY.get("staging_distribution", 0))
    event["published"] = bool(POLICY.get("staged_published", False))
    for a in event.get("Attribute") or []:
        a.setdefault("distribution", 5)          # inherit the event level

    notes = []
    prior = {"objects": set(), "reports": {}}
    if misp_configured():                        # type validation needs the instance to answer
        event, notes = validate_event(event)
        if event_id:
            prior = existing_event(event_id)
    skipped_objects = 0
    if prior["objects"] and event.get("Object"):
        keep = []
        for o in event["Object"]:
            key = (str(o.get("name")),
                   "|".join(sorted(str(a.get("value")) for a in (o.get("Attribute") or []))))
            if key in prior["objects"]:
                skipped_objects += 1
            else:
                keep.append(o)
        event["Object"] = keep
    if dry_run:                                  # inspectable with no instance configured
        return {"ok": True, "sent": False, "dry_run": True,
                "request": {"method": "POST",
                            "path": (ENDPOINTS["edit_event"].format(event_id=event_id)
                                     if event_id else ENDPOINTS["add_event"]),
                            "body": {"Event": event}},
                "type_notes": notes}
    if not misp_configured():
        return {"ok": False, "sent": False, "error": REPORTING.get("not_configured")}

    path = (ENDPOINTS["edit_event"].format(event_id=event_id) if event_id
            else ENDPOINTS["add_event"])
    r = _request("POST", path, {"Event": event})
    if not r["ok"]:
        return {"ok": False, "sent": False, "error": r.get("error"), "status": r.get("status")}
    got = ((r["data"] or {}).get("Event") or {})
    new_id = got.get("id") or event_id
    reports, report_errors = 0, []
    for rep in (export.get("EventReport") or []):
        rr = put_event_report(new_id, rep, prior.get("reports"))
        if rr["ok"]:
            reports += 1
        else:
            report_errors.append(rr.get("error"))
    result = {
        "ok": True, "sent": True,
        "event_id": new_id, "event_uuid": got.get("uuid"),
        "attributes_sent": len(event.get("Attribute") or []),
        "objects_sent": len(event.get("Object") or []),
        "objects_already_present": skipped_objects,
        "event_reports_attached": reports,
        "distribution": event["distribution"], "published": False,
        "url": (base_url() + ENDPOINTS.get("event_ui", "/events/view/{event_id}").format(
            event_id=got.get("id") or event_id)) if base_url() else None,
        "type_notes": notes,
        "state": REPORTING.get("staged_note"),
        "next": ("If the analyst wants this SHARED, that is the separate publish step: it raises "
                 "distribution and notifies peers, and it cannot be undone."),
    }
    if report_errors:
        result["event_report_errors"] = report_errors
        result["warning"] = ("the indicators were staged but the NARRATIVE did not attach — the "
                             "event now carries values with none of their caveats. Fix and re-push "
                             "before sharing it.")
    _ledger(case, "push", result, meta)

    if publish:
        pub = globals()["publish"](new_id, distribution=int(distribution or 1), confirm=True,
                                   case=case)
        result["publish"] = pub
        if pub.get("sent"):
            result["published"] = True
            result["distribution"] = pub.get("distribution")
            result["state"] = ("PUBLISHED — " + str(pub.get("irreversible") or ""))
        else:
            result["state"] = (str(REPORTING.get("staged_note")) + " The publish step did NOT "
                               "run: " + str(pub.get("blocked_by") or pub.get("error")
                                             or "confirmation or the environment lock is missing")
                               + " The event is staged and can be published later.")
    return result


def publish_briefing(event_id, distribution: int, *, event: dict | None = None) -> dict:
    """What publishing would do, in the terms that decide it: who receives it, and that it is
    final. Returned INSTEAD of acting when confirmation or the environment lock is absent."""
    d = _dist_entry(distribution)
    lock = str(POLICY.get("publish_env_lock") or "INTEL_MISP_PUBLISH")
    ev = event or {}
    summary = _attr_summary(ev) if ev else None
    pii = [a.get("value") for a in (ev.get("Attribute") or [])
           if str(a.get("category")) in ("Attribution", "Social network")][:15]
    return {
        "action": "CONFIRMATION REQUIRED — the event is NOT published; nothing has left the "
                  "instance",
        "instance": base_url() or "(not configured)",
        "event_id": event_id,
        "requested_distribution": {"level": distribution, "name": d.get("name"),
                                   "audience": d.get("who"), "recallable": d.get("recallable")},
        "attributes": summary,
        "personal_data_in_event": pii,
        "irreversible": True,
        "why_it_is_gated": REPORTING.get("publish_irreversible"),
        "consider_first": [
            "Search the instance for each strong indicator — a value the community already holds "
            "does not need re-sharing (sh_misp.py search <value>).",
            "Re-read the to_ids attributes: those become other people's blocking rules.",
            "Confirm the TLP tag matches what the source of the material allows you to share.",
            "On threat-actor infrastructure, publishing can collide with somebody else's live "
            "operation and tells the actor they are tracked — coordinate first.",
        ],
        "will_not": ["publish without an explicit yes to THIS event",
                     "raise distribution beyond the level the analyst names"],
        "to_proceed": (f"Ask the analyst explicitly whether this should be shared and at which "
                       f"level, then call publish(..., confirm=True); the run must also have "
                       f"{lock}=1 — CLI: sh_misp.py publish {event_id} --distribution "
                       f"<level> --confirm-publish"),
    }


def publish(event_id, *, distribution: int = 1, confirm: bool = False, case: str = "",
            sharing_group_id=None, dry_run: bool = False) -> dict:
    """Raise the event's distribution and publish it. The irreversible step."""
    lock = str(POLICY.get("publish_env_lock") or "INTEL_MISP_PUBLISH")
    locked = os.environ.get(lock, "").strip().lower() in ("1", "true", "yes", "on")
    event = None
    if misp_configured():
        got = _request("GET", ENDPOINTS.get("get_event", "/events/view/{event_id}").format(
            event_id=event_id))
        if got["ok"]:
            event = ((got["data"] or {}).get("Event") or {})

    if not confirm or not locked:
        b = publish_briefing(event_id, distribution, event=event)
        if confirm and not locked:
            b["blocked_by"] = (f"the analyst confirmed, but the environment lock {lock}=1 is not "
                               f"set for this run. That lock is a human's act, not an agent's: "
                               f"re-launch with {lock}=1 once the analyst has agreed.")
        return b
    if int(distribution) == 4 and not sharing_group_id:
        return {"ok": False, "sent": False,
                "error": "distribution 4 is a SHARING GROUP and needs sharing_group_id — without "
                         "it MISP cannot know the audience, and neither can you."}
    if not misp_configured():
        return {"ok": False, "sent": False, "error": REPORTING.get("not_configured")}

    payload = {"Event": {"id": str(event_id), "distribution": int(distribution)}}
    if sharing_group_id:
        payload["Event"]["sharing_group_id"] = str(sharing_group_id)
    if dry_run:
        return {"ok": True, "sent": False, "dry_run": True, "requests": [
            {"method": "POST", "path": ENDPOINTS["edit_event"].format(event_id=event_id),
             "body": payload},
            {"method": "POST", "path": ENDPOINTS["publish_event"].format(event_id=event_id)}]}

    r1 = _request("POST", ENDPOINTS["edit_event"].format(event_id=event_id), payload)
    if not r1["ok"]:
        return {"ok": False, "sent": False, "stage": "set-distribution", "error": r1.get("error")}
    r2 = _request("POST", ENDPOINTS["publish_event"].format(event_id=event_id))
    if not r2["ok"]:
        return {"ok": False, "sent": False, "stage": "publish", "error": r2.get("error"),
                "note": "The distribution WAS raised before publishing failed — the event is now "
                        "visible at the new level on this instance even though no sync was "
                        "triggered. Re-run publish or lower the distribution deliberately."}
    d = _dist_entry(distribution)
    result = {"ok": True, "sent": True, "published": True, "event_id": str(event_id),
              "distribution": int(distribution), "audience": d.get("who"),
              "url": (base_url() + ENDPOINTS.get("event_ui", "/events/view/{event_id}").format(
                  event_id=event_id)) if base_url() else None,
              "irreversible": REPORTING.get("publish_irreversible")}
    _ledger(case, "publish", result, {})
    return result


# --------------------------------------------------------------------------- local ledger
def _ledger(case: str, action: str, result: dict, meta: dict) -> None:
    """One line per outbound share, next to the case. Answers 'what did we send, when, to whom'
    long after the run — the sharing counterpart of the tool-call ledger."""
    if not case:
        return
    path = os.path.join(_repo_root(), "cases", str(case), "misp", "ledger.jsonl")
    row = {"ts": _utcnow(), "action": action, "instance": base_url(),
           "event_id": result.get("event_id"), "event_uuid": result.get("event_uuid"),
           "distribution": result.get("distribution"), "published": result.get("published", False),
           "attributes": result.get("attributes_sent"), "ok": result.get("ok"),
           "built_at": meta.get("built_at")}
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    except OSError as e:
        print(f"[misp] WARNING: share ledger unwritable ({e}); the push happened but is NOT "
              f"recorded locally.", file=sys.stderr)


# --------------------------------------------------------------------------- CLI
def _main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="MISP instance client — staging push and gated "
                                             "publish. Read-only unless you confirm.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keycheck", help="configured / reachable / version (sends no case data)")
    sub.add_parser("budget", help="requests used this run (offline)")

    s = sub.add_parser("search", help="is this indicator already known to the instance?")
    s.add_argument("value")
    s.add_argument("--type", dest="type_", default="")
    s.add_argument("--limit", type=int, default=25)

    p = sub.add_parser("push", help="stage an exported event (organisation-only, unpublished)")
    p.add_argument("event_file")
    p.add_argument("--event-id", default=None, help="update this event instead of creating one")
    p.add_argument("--case", default="")
    p.add_argument("--confirm-push", action="store_true",
                   help="the analyst said yes to staging THIS event")
    p.add_argument("--publish", action="store_true",
                   help="ALSO publish once staged. Still requires INTEL_MISP_PUBLISH=1 — without "
                        "it the event stays staged and the result says so")
    p.add_argument("--distribution", type=int, default=1,
                   help="audience for --publish (1 community · 2 connected · 3 all · 4 group)")
    p.add_argument("--dry-run", action="store_true", help="print the request, send nothing")

    b = sub.add_parser("publish", help="raise distribution and publish — IRREVERSIBLE")
    b.add_argument("event_id")
    b.add_argument("--distribution", type=int, default=1)
    b.add_argument("--sharing-group-id", default=None)
    b.add_argument("--case", default="")
    b.add_argument("--confirm-publish", action="store_true",
                   help="the analyst said yes to SHARING this event at this level")
    b.add_argument("--dry-run", action="store_true")
    ap.add_argument("--pretty", action="store_true")

    a = ap.parse_args(argv)
    if a.cmd == "keycheck":
        out = keycheck()
    elif a.cmd == "budget":
        out = budget_status()
    elif a.cmd == "search":
        out = search(a.value, type_=a.type_, limit=a.limit)
    elif a.cmd == "push":
        out = push(a.event_file, confirm=a.confirm_push, event_id=a.event_id, case=a.case,
                   dry_run=a.dry_run, publish=a.publish, distribution=a.distribution)
    else:
        out = publish(a.event_id, distribution=a.distribution, confirm=a.confirm_publish,
                      case=a.case, sharing_group_id=a.sharing_group_id, dry_run=a.dry_run)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(_main())
