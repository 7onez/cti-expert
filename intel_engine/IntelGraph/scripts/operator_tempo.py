#!/usr/bin/env python3
"""
operator_tempo.py — the OPERATOR TEMPO read behind `case_timeline.py --tempo`: at what local hours
and weekdays does this operator act, and which UTC offsets would make that a working day?

WHY THIS EXISTS
---------------
A case holds hundreds of timestamps, and almost none of them record a human decision. A CT log
entry, a Let's Encrypt renewal, a Wayback capture, a passive-DNS first-seen and a urlscan
submission are all stamped by somebody else's machine; a histogram of them describes crawler
schedules. The few that ARE operator-chosen — git author times, post and message times, manual
panel actions, a hand-ordered certificate, a hand-placed registration — can show a rhythm, and a
rhythm that fits one zone's business hours is a useful LEAD for monitoring windows, for testing a
claimed location, and for noticing that two "teams" keep two different clocks.

Adapted from the "two distinct activity rhythms" timing read in the Packt ACTIH companion repo
(MIT, (c) 2026 Packt) [PK Packt ACTIH companion repo, 2026, chapter-03 threat-profile
deliverable]. The event filter, the offset scan, the
abstention floor and the residue test for a second rhythm are our adaptation.

PROCEDURE (handbook/intrusion-modeling.md "Operator tempo")
---------
  1. select   keep only operator-chosen timestamps (references/operator_tempo.json); every drop
              is recorded with its reason — automated certificate issuers, crawl/scan/observation
              kinds, date-only (00:00:00) stamps, bot committers, same-session bursts
  2. count    hour-of-day x weekday histogram in UTC
  3. abstain  fewer than min_events across min_distinct_days -> status 'insufficient', no offsets
  4. scan     every candidate UTC offset: share of events in the local working window
              (default Mon-Fri 09:00-18:00) and in the after-hours window (23:00-06:00, the same
              definition as signature-catalog T-02); rank and report the top offsets
  5. residue  hours only: events outside a candidate offset's working HOURS (any weekday): if
              enough of them sit in one window-wide band that does not overlap the primary band,
              and the two bands clearly out-cover the best single band of hours, flag a SECOND
              RHYTHM and give both readings (the primary zone's off-hours, or a second zone's
              day); weekday/weekend share is an attribute of each band, never a band of its own

RAILS — LEAD ONLY
-----------------
The result is an analyst judgement about rhythm. It is never attribution, never a same-operator
edge, never a clustering input, and nothing here touches the knowledge base: the module imports no
KB code and returns a dict the caller writes into the timeline ledger. Confounders ride with every
read, whatever the verdict.
"""
import email.utils
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ig_refs import load_ref, ref_path                       # noqa: E402

# Minimal embedded fallback — the real, extensible data lives in references/operator_tempo.json
# (contributor RULE 3). On this fallback the offset scan skips half-hour zones, fewer automated
# issuers are recognised and the confounder list shrinks: the JSON failed to load.
_FALLBACK = {
    "settings": {"min_events": 30, "min_distinct_days": 10, "top_n": 5, "consistent_margin": 0.05,
                 "min_working_share": 0.5, "burst_collapse_minutes": 10,
                 "drop_midnight_exact": True, "max_listed_exclusions": 50,
                 "two_rhythm_min_share": 0.2, "two_rhythm_min_events": 10,
                 "two_rhythm_min_working_share": 0.6, "two_rhythm_min_coverage_gain": 0.2},
    "working_window": {"start_hour": 9, "end_hour": 18, "days": [0, 1, 2, 3, 4]},
    "after_hours_window": {"start_hour": 23, "end_hour": 6},
    "offsets": list(range(-12, 15)),
    "operator_kinds": {"commit_author": "git author time", "post": "post time",
                       "message": "message time", "panel_action": "manual panel action"},
    "timeline_kinds": {"registration": {"include": True, "reason": "registrar-stamped purchase"},
                       "cert": {"include": "issuer_check", "reason": "manual issuance only"}},
    "automated_cert_issuers": ["let's encrypt", "zerossl", "google trust services"],
    "bot_identity_patterns": ["[bot]", "dependabot", "github-actions"],
    "confounders": ["automation or schedulers", "shift work and outsourcing",
                    "deliberate offsets or VPN", "DST", "mixed team", "platform server time"],
}
_REF = load_ref(ref_path(__file__, "operator_tempo.json"), _FALLBACK)
SETTINGS = {**_FALLBACK["settings"], **(_REF.get("settings") or {})}
WORK = {**_FALLBACK["working_window"], **(_REF.get("working_window") or {})}
AFTER = {**_FALLBACK["after_hours_window"], **(_REF.get("after_hours_window") or {})}
OFFSETS = [float(o) for o in _REF["offsets"]]
OPERATOR_KINDS = _REF["operator_kinds"]
TIMELINE_KINDS = _REF["timeline_kinds"]
AUTOMATED_ISSUERS = [s.lower() for s in _REF["automated_cert_issuers"]]
BOT_PATTERNS = [s.lower() for s in _REF["bot_identity_patterns"]]
CONFOUNDERS = list(_REF["confounders"])

WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
RAIL = ("LEAD ONLY — a working-hours offset is an analyst judgement about rhythm: never "
        "attribution, never a same-operator edge, never a clustering input; nothing here is "
        "written to the knowledge base.")


# --------------------------------------------------------------------- helpers
def fmt_offset(off):
    """3 -> '+3', -3.5 -> '-3:30', 5.75 -> '+5:45'."""
    sign = "-" if off < 0 else "+"
    h, m = divmod(round(abs(off) * 60), 60)
    return f"{sign}{h}" + (f":{m:02d}" if m else "")


def _in_band(hour, start, end):
    """hour in [start, end) on a 24 h circle (start > end wraps past midnight)."""
    return start <= hour < end if start <= end else (hour >= start or hour < end)


def _hhmm(hour):
    h, m = divmod(round(hour * 60) % 1440, 60)
    return f"{h:02d}:{m:02d}"


def _frac_hour(dt):
    return dt.hour + dt.minute / 60 + dt.second / 3600


def _to_utc(value):
    """ISO / RFC 2822 / epoch -> aware UTC datetime, or None. Kept local so the module stays
    importable on its own; case_timeline passes already-parsed datetimes."""
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(value or "").strip()
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        try:
            dt = email.utils.parsedate_to_datetime(s)
        except (TypeError, ValueError, IndexError):
            return None
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _cand(when, kind, source, host="", url=None, note=""):
    return {"when": when, "kind": kind, "source": source, "host": host or "", "url": url,
            "note": note}


# --------------------------------------------------------------------- 1. select
def from_timeline(events, keep, drop):
    """case_timeline rows -> operator-chosen candidates; every other row is dropped with a reason."""
    for e in events:
        if not e:
            continue
        kind, when = e.get("kind"), e.get("_start")
        rule = TIMELINE_KINDS.get(kind)
        if not rule:
            drop(kind, when, e.get("host"), "kind not an operator-chosen timestamp "
                                            "(not listed in operator_tempo.json timeline_kinds)")
            continue
        inc = rule.get("include")
        if inc == "issuer_check":
            issuer = str(((e.get("value") or {}).get("issuer")) or e.get("label") or "").lower()
            hit = next((a for a in AUTOMATED_ISSUERS if a in issuer), None)
            if hit:
                drop(kind, when, e.get("host"),
                     f"automated certificate issuance ({hit}) — a renewal job's clock, not the operator's")
                continue
            if not issuer or "unknown" in issuer:
                drop(kind, when, e.get("host"), "certificate issuer unknown — cannot rule out automated issuance")
                continue
        elif not inc:
            drop(kind, when, e.get("host"), rule.get("reason") or "excluded kind")
            continue
        keep(_cand(when, kind, e.get("source") or "", e.get("host"), e.get("url"),
                   rule.get("reason") or ""))


def _is_bot(author):
    blob = f"{author.get('name') or ''} {author.get('email') or ''} {author.get('login') or ''}".lower()
    return next((p for p in BOT_PATTERNS if p in blob), None)


_TZ_TAIL = re.compile(r"([+-]\d{4})\s*$")


def from_github(doc, keep, drop, declared):
    """github_harvest output -> commit author times; the .patch Date header's own offset is tallied
    separately (the committer machine's declared zone — a lead with its own confounder)."""
    owner = str(((doc.get("meta") or {}).get("host")) or doc.get("owner") or "github")
    for repo in doc.get("repos") or []:
        for c in repo.get("commits_sampled") or []:
            author = c.get("author") or {}
            patch = c.get("patch") or {}
            when = _to_utc(c.get("date")) or _to_utc(patch.get("date"))
            m = _TZ_TAIL.search(str(patch.get("date") or ""))
            if m:
                declared[m.group(1)] += 1
            bot = _is_bot(author) or _is_bot({"name": patch.get("name"), "email": patch.get("email")})
            if bot:
                drop("commit_author", when, owner, f"automated committer ({bot})")
                continue
            if not when:
                drop("commit_author", None, owner, "commit carries no parseable author time")
                continue
            keep(_cand(when, "commit_author", "github", owner, c.get("url"),
                       OPERATOR_KINDS.get("commit_author", "")))


def from_operator_events(doc, keep, drop):
    """Generic `operator_events` rows ({when, kind, source, host?, url?}) — post/message times,
    panel actions, logins the analyst lawfully holds."""
    for row in doc.get("operator_events") or []:
        if not isinstance(row, dict):
            continue
        kind, when = str(row.get("kind") or ""), _to_utc(row.get("when"))
        if kind not in OPERATOR_KINDS:
            drop(kind, when, row.get("host"), "kind not in operator_tempo.json operator_kinds")
            continue
        if not when:
            drop(kind, None, row.get("host"), "no parseable timestamp")
            continue
        keep(_cand(when, kind, str(row.get("source") or ""), row.get("host"), row.get("url"),
                   OPERATOR_KINDS.get(kind, "")))


def select(timeline_events=(), docs=()):
    """Returns (kept candidates, exclusions). Applies the date-only and burst rules last so they
    see every source."""
    kept, excluded, declared = [], [], Counter()

    def drop(kind, when, host, reason):
        excluded.append({"kind": kind, "when": when.strftime("%Y-%m-%dT%H:%M:%SZ") if when else None,
                         "host": host or "", "reason": reason})

    from_timeline(timeline_events, kept.append, drop)
    for d in docs:
        if not isinstance(d, dict):
            continue
        if (d.get("meta") or {}).get("kind") == "github" or d.get("commits_sampled") is not None:
            from_github(d, kept.append, drop, declared)
        if d.get("operator_events"):
            from_operator_events(d, kept.append, drop)

    out, seen, last = [], set(), {}
    burst = timedelta(minutes=float(SETTINGS["burst_collapse_minutes"]))
    for c in sorted(kept, key=lambda x: x["when"]):
        w = c["when"]
        key = (c["kind"], c["host"], w)
        if key in seen:
            continue                                    # the same fact via two collectors
        seen.add(key)
        if SETTINGS["drop_midnight_exact"] and (w.hour, w.minute, w.second) == (0, 0, 0):
            drop(c["kind"], w, c["host"], "date-only precision (00:00:00) — the hour is unknown, not midnight")
            continue
        prev = last.get((c["kind"], c["host"]))
        if prev is not None and w - prev < burst:
            drop(c["kind"], w, c["host"], "same-session burst collapsed — one decision, counted once")
            continue
        last[(c["kind"], c["host"])] = w
        out.append(c)
    return out, excluded, declared


# --------------------------------------------------------------------- 2-5. read
def histogram(cands):
    grid = [[0] * 24 for _ in range(7)]
    for c in cands:
        grid[c["when"].weekday()][c["when"].hour] += 1
    return {"weekday_labels": WEEKDAYS, "weekday_hour": grid,
            "hour": [sum(grid[d][h] for d in range(7)) for h in range(24)],
            "weekday": [sum(row) for row in grid]}


def score_offset(times, off):
    """Shares of `times` (UTC datetimes) in the working / after-hours / weekend windows at `off`."""
    n = len(times) or 1
    work = after = weekend = 0
    for t in times:
        loc = t + timedelta(hours=off)
        h = _frac_hour(loc)
        if loc.weekday() in WORK["days"] and _in_band(h, WORK["start_hour"], WORK["end_hour"]):
            work += 1
        if _in_band(h, AFTER["start_hour"], AFTER["end_hour"]):
            after += 1
        if loc.weekday() not in WORK["days"]:
            weekend += 1
    return {"offset": fmt_offset(off), "offset_hours": off, "working_share": round(work / n, 3),
            "after_hours_share": round(after / n, 3), "non_workday_share": round(weekend / n, 3)}


def rank_offsets(times):
    rows = [score_offset(times, o) for o in OFFSETS]
    return sorted(rows, key=lambda r: (-r["working_share"], r["after_hours_share"], abs(r["offset_hours"])))


def _circ(a, b):
    d = abs(a - b) % 24
    return min(d, 24 - d)


def _same_reading(a, b):
    """Clock aliases (UTC-12/UTC+12, -11/+13, -10/+14) sit a calendar day apart, so they read
    the same only when their weekday-dependent shares agree too."""
    return all(a.get(k) == b.get(k) for k in ("working_share", "non_workday_share"))


def _range(rows, alias_rows=None):
    a, b = fmt_offset(rows[0]["offset_hours"]), fmt_offset(rows[-1]["offset_hours"])
    label = f"UTC{a}" if a == b else f"UTC{a} to UTC{b}"
    out = {"start": a, "end": b, "span_hours": rows[-1]["offset_hours"] - rows[0]["offset_hours"],
           "offsets": [fmt_offset(r["offset_hours"]) for r in rows], "label": label}
    if alias_rows:
        x, y = fmt_offset(alias_rows[0]["offset_hours"]), fmt_offset(alias_rows[-1]["offset_hours"])
        same = f"UTC{x}" if x == y else f"UTC{x} to UTC{y}"
        out["alias_offsets"] = [fmt_offset(r["offset_hours"]) for r in alias_rows]
        out["label"] += f" (same weekday shares as {same})"
    return out


def consistent_ranges(ranked, margin):
    """Runs of qualifying SIGNED offsets, adjacent in the candidate list — never a min/max
    envelope, never a bridge over a non-qualifying candidate, never a substituted alias.

    UTC-12 and UTC+12 (likewise -11/+13 and -10/+14) share a clock position but not a
    calendar day, so the first and last runs join across the date line only when every
    clock position they share qualifies on both sides with identical weekday shares.
    """
    best = ranked[0]["working_share"]
    rows = sorted(ranked, key=lambda r: r["offset_hours"])
    if all(best - r["working_share"] <= margin for r in rows):
        return [{"start": None, "end": None, "span_hours": 24,
                 "offsets": [fmt_offset(r["offset_hours"]) for r in rows], "label": "all candidate UTC offsets"}]
    runs, run = [], []
    for r in rows:
        if best - r["working_share"] <= margin:
            run.append(r)
        elif run:
            runs.append(run)
            run = []
    if run:
        runs.append(run)
    if len(runs) > 1:
        lo = {r["offset_hours"] % 24: r for r in runs[0]}
        hi = {r["offset_hours"] % 24: r for r in runs[-1]}
        shared = lo.keys() & hi.keys()
        if shared and all(_same_reading(lo[p], hi[p]) for p in shared):
            if lo.keys() <= hi.keys():
                return [_range(r) for r in runs[1:-1]] + [_range(runs[-1], runs[0])]
            if hi.keys() <= lo.keys():
                return [_range(runs[0], runs[-1])] + [_range(r) for r in runs[1:-1]]
            merged = runs[-1] + [r for r in runs[0] if r["offset_hours"] % 24 not in shared]
            out = _range(merged)
            out["span_hours"] %= 24
            out["label"] += " (across the date line)"
            return [_range(r) for r in runs[1:-1]] + [out]
    return [_range(r) for r in runs]


def _alt_offset(start_utc):
    """Offset that puts a band starting at `start_utc` (UTC hour) at the local working start."""
    x = (WORK["start_hour"] - start_utc) % 24
    return x - 24 if x > 14 else x


def _band_width():
    return (WORK["end_hour"] - WORK["start_hour"]) % 24 or 24


def _band_count(hours, start, width):
    """Events whose UTC hour falls in [start, start+width) on the 24 h circle — hours only."""
    return sum(_in_band(h, start % 24, (start + width) % 24) for h in hours)


def second_rhythm(times, primary):
    """Hours only: events outside the primary working HOURS (any weekday — a weekend post inside the
    primary hours is the same rhythm, not residue). Does enough of that residue fall in one
    window-wide band of hours that does not overlap the primary band (start-to-start separation of
    at least the window width)? Weekday/weekend is reported as an attribute of each band, never as
    a band of its own. Both readings are returned — the primary zone's off-hours, or a second
    zone's working day."""
    off = primary["offset_hours"]
    width = _band_width()
    prim_start = (WORK["start_hour"] - off) % 24
    prim_end = (prim_start + width) % 24
    in_prim = [t for t in times if _in_band(_frac_hour(t), prim_start, prim_end)]
    resid = [t for t in times if not _in_band(_frac_hour(t), prim_start, prim_end)]
    need = max(int(SETTINGS["two_rhythm_min_events"]), SETTINGS["two_rhythm_min_share"] * len(times))
    res = {"flagged": False, "primary_offset": primary["offset"], "primary_band_events": len(in_prim),
           "residue_events": len(resid),
           "residue_needed": int(need) if need == int(need) else round(need, 1)}
    if len(resid) < need:
        res["reason"] = "too few events outside the primary working hours"
        return res
    starts = [s for s in range(24) if _circ(s, prim_start) >= width - 1e-9]
    if not starts:
        res["reason"] = "the working window is wider than half a day — no room for a separate band"
        return res
    rh = [_frac_hour(t) for t in resid]
    best = max(starts, key=lambda s: (_band_count(rh, s, width), -s))
    end = (best + width) % 24
    band = [t for t in resid if _in_band(_frac_hour(t), best, end)]
    share = len(band) / len(resid)
    res.update({"band_utc": f"{best:02d}:00-{end:02d}:00 UTC", "band_share_of_residue": round(share, 3),
                "band_events": len(band), "separation_hours": round(_circ(best, prim_start), 2),
                "coverage_events": len(in_prim) + len(band),
                "primary_band_non_workday_share": score_offset(in_prim, off)["non_workday_share"],
                "band_non_workday_share": score_offset(band, off)["non_workday_share"]})
    if share < SETTINGS["two_rhythm_min_working_share"]:
        res["reason"] = "events outside the primary working hours are scattered, not a second band"
        return res
    # A uniform clock already places width/(24-width) of the residue in any disjoint
    # width-hour band (9/15 = 60% by default). Coverage gain alone would manufacture two
    # rhythms from round-the-clock activity; require actual concentration above that baseline.
    if len(band) * (24 - width) <= len(resid) * width:
        res["reason"] = "the second band is no more concentrated than uniform round-the-clock activity"
        return res
    alt = _alt_offset(best)
    at_primary = score_offset(band, off)
    res.update({
        "flagged": True,
        "readings": [
            f"the primary zone's off-hours: at UTC{primary['offset']} the band starts at local "
            f"{_hhmm((best + off) % 24)} ({at_primary['after_hours_share']:.0%} in 23:00-06:00, "
            f"{at_primary['non_workday_share']:.0%} on non-workdays)",
            f"a second zone's working day: the band fits UTC{fmt_offset(alt)} business hours",
        ],
        "secondary_offset": fmt_offset(alt),
        "caution": "two activity rhythms — possible mixed team, shift handover, a separate after-hours "
                   "line of work, or two actors on shared infrastructure; do not merge or split actors on "
                   "this alone",
    })
    return res


def two_rhythms(times, ranked):
    """Try every candidate offset as the primary rhythm. In a bimodal set the best SINGLE offset is
    a blend that straddles both bands, so the pair is chosen by coverage instead. Coverage is hours
    only on both sides: flagged only when primary band + second band hold at least
    max(two_rhythm_min_events, two_rhythm_min_coverage_gain x n) more events than the best single
    window-wide band of hours (any weekday)."""
    n = len(times)
    width = _band_width()
    hours = [_frac_hour(t) for t in times]
    starts = sorted({(WORK["start_hour"] - o) % 24 for o in OFFSETS} | set(range(24)))
    single = max(_band_count(hours, s, width) for s in starts)
    need = max(int(SETTINGS["two_rhythm_min_events"]), SETTINGS["two_rhythm_min_coverage_gain"] * n)
    floor = {"single_window_events": single, "single_window_share": round(single / (n or 1), 3)}
    pairs = [r for r in (second_rhythm(times, p) for p in ranked)
             if r["flagged"] and r["coverage_events"] - single >= need]
    if not pairs:
        res = dict(second_rhythm(times, ranked[0]), **floor)
        if res["flagged"]:                              # the band is real but adds too little
            res["flagged"] = False
            res["reason"] = (f"a second band exists but adds fewer than {need:g} events beyond the best "
                             "single window — read it as one rhythm with a long tail")
        return res
    return dict(max(pairs, key=lambda r: r["coverage_events"]), **floor)  # max() keeps the first tie


def analyze(timeline_events=(), docs=()):
    """The full tempo read. Pure: returns a dict, writes nothing."""
    cands, excluded, declared = select(timeline_events, docs)
    times = [c["when"] for c in cands]
    days = len({t.date() for t in times})
    min_n, min_d = int(SETTINGS["min_events"]), int(SETTINGS["min_distinct_days"])
    by_reason = Counter(e["reason"] for e in excluded)
    cap = int(SETTINGS["max_listed_exclusions"])
    out = {
        "lead_only": True, "rail": RAIL, "kb_write": False,
        "events_used": len(times), "distinct_days": days,
        "by_kind": dict(Counter(c["kind"] for c in cands)),
        "excluded": {"total": len(excluded), "by_reason": dict(by_reason.most_common()),
                     "listed": excluded[:cap], "listed_truncated": max(0, len(excluded) - cap)},
        "windows": {"working": f"local {WORK['start_hour']:02d}:00-{WORK['end_hour']:02d}:00 "
                               + ",".join(WEEKDAYS[d] for d in WORK["days"]),
                    "after_hours": f"local {AFTER['start_hour']:02d}:00-{AFTER['end_hour']:02d}:00 "
                                   "any day (signature-catalog T-02)"},
        "thresholds": {"min_events": min_n, "min_distinct_days": min_d,
                       "min_working_share": SETTINGS["min_working_share"]},
        "histogram_utc": histogram(cands),
        "declared_author_utc_offsets": dict(declared.most_common()),
        "offsets": [], "consistent_offsets": [], "two_rhythms": {"flagged": False},
        "confounders": CONFOUNDERS,
    }
    if declared:
        out["declared_author_note"] = ("git .patch Date offsets are the committer machine's TZ setting "
                                       "— trivially changed; a lead to set beside the histogram, not proof")
    if len(times) < min_n or days < min_d:
        out["status"] = "insufficient"
        out["finding"] = (f"insufficient — {len(times)} operator-chosen event(s) across {days} day(s); "
                          f"the floor is {min_n} across {min_d}. No tempo read.")
        return out
    ranked = rank_offsets(times)
    best = ranked[0]
    margin = float(SETTINGS["consistent_margin"])
    out["offsets"] = ranked[:int(SETTINGS["top_n"])]
    out["consistent_offsets"] = [r["offset"] for r in sorted(ranked, key=lambda r: r["offset_hours"])
                                 if best["working_share"] - r["working_share"] <= margin]
    out["two_rhythms"] = two_rhythms(times, ranked)
    ranges = consistent_ranges(ranked, margin)
    ranges.sort(key=lambda r: best["offset"] not in r.get("offsets", []) + r.get("alias_offsets", []))
    out["consistent_offset_ranges"] = ranges
    span = ranges[0]["label"]
    primary = {r["offset_hours"] % 24: r for r in ranked
               if r["offset"] in ranges[0].get("offsets", [])}
    others = []
    for group in ranges[1:]:
        label = group["label"]
        if len(group.get("offsets", [])) == 1:
            row = next(r for r in ranked if r["offset"] == group["offsets"][0])
            alias = primary.get(row["offset_hours"] % 24)
            if alias and not _same_reading(row, alias):
                label += (f" (calendar-day alias of UTC{alias['offset']}; "
                          "differs only in which weekday is local)")
        others.append(label)
    if others:
        span += "; also consistent: " + " or ".join(others)
    if best["working_share"] < SETTINGS["min_working_share"] and not out["two_rhythms"]["flagged"]:
        out["status"] = "no_clear_window"
        out["finding"] = (f"no offset puts {SETTINGS['min_working_share']:.0%} of {len(times)} events in a "
                          f"local working window (best UTC{best['offset']} at {best['working_share']:.0%}) — "
                          "round-the-clock or irregular activity; no timezone lead.")
        return out
    out["status"] = "lead"
    out["finding"] = (f"Activity concentrates in a window consistent with UTC{best['offset']} business hours "
                      f"({best['working_share']:.0%} of {len(times)} events across {days} days in "
                      f"{out['windows']['working']}; consistent range {span}) — lead.")
    if out["two_rhythms"]["flagged"]:
        tr = out["two_rhythms"]
        k1 = tr["coverage_events"] - tr["band_events"]
        out["finding"] = (f"Two activity rhythms: a window consistent with UTC{tr['primary_offset']} business "
                          f"hours ({k1} of {len(times)} events across {days} days) and a second band "
                          f"{tr['band_utc']} ({tr['band_events']} events) that fits either UTC"
                          f"{tr['primary_offset']} off-hours or UTC{tr['secondary_offset']} business hours; "
                          f"the single-offset ranking (best UTC{best['offset']}) blends the two — lead.")
    return out


def markdown(tempo):
    """Short paste-ready block for the timeline markdown."""
    L = ["", "## Operator tempo (lead only)", "", f"**{tempo.get('status')}** — {tempo.get('finding')}", ""]
    if tempo.get("offsets"):
        L += ["| UTC offset | working share | after-hours share | non-workday share |", "|---|---|---|---|"]
        L += [f"| UTC{r['offset']} | {r['working_share']:.0%} | {r['after_hours_share']:.0%} | "
              f"{r['non_workday_share']:.0%} |" for r in tempo["offsets"]]
        L.append("")
    ex = tempo.get("excluded") or {}
    if ex.get("total"):
        L.append(f"Excluded {ex['total']} timestamp(s): "
                 + "; ".join(f"{n}× {r}" for r, n in list(ex["by_reason"].items())[:6]) + ".")
        L.append("")
    L.append("Confounders: " + "; ".join(tempo.get("confounders") or []) + ".")
    L += ["", f"_{RAIL}_", ""]
    return "\n".join(L)
