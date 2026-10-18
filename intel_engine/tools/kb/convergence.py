#!/usr/bin/env python3
"""
convergence.py — an explicit STOP CONDITION for an investigation.

WHY THIS EXISTS
---------------
Pivoting can sprawl forever: every host yields more queries, and without a defined
finish line you either stop arbitrarily (missing the tail) or chase diminishing returns
(burning time on noise). This tool tracks how much NEW an investigation is still
producing each round and gives a plain verdict — CONVERGED or EXPANDING — plus a budget
check. "Converged" = the last N pivot rounds added no new hosts and no new indicators;
that's the signal to stop pivoting and write the assessment.

HOW IT MEASURES
---------------
A "round" is a snapshot of the case's `raw/*.json`. Each snapshot records the set of
hosts and the set of high-signal, NOISE-FILTERED indicators (favicon, trackers, wallets,
SaaS tokens, verifications, QR payloads, registrant emails, mail infrastructure — M365
tenant, custom MX, SPF single-host IPs) present in the case. Round
over round it reports how many were newly added. Noise indicators (managed-DNS NS,
parking favicon, registrar/privacy emails, malformed GA4) are excluded via noise_filters,
so a round that only pulled in junk correctly reads as "no real growth."

USAGE
-----
  # after each pivot round (re-ran domains, added hosts to the case):
  python3 tools/kb/convergence.py snapshot <case>

  # verdict + history:
  python3 tools/kb/convergence.py status <case> --stale 2 --budget-hosts 50

Snapshots are stored in cases/<case>/rounds.jsonl.
"""
import argparse
import glob
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from noise_filters import is_noise_indicator, is_noise_email
except Exception:  # graceful degrade
    def is_noise_indicator(_):
        return False
    def is_noise_email(_):
        return False

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _case_dir(case):
    return case if os.path.isdir(case) else os.path.join(REPO, "cases", case)


def _indicators_from_raw(obj):
    """Extract the set of high-signal, noise-filtered indicator strings from one raw
    pivot_extract JSON (same spirit as the KB ingester, kept lightweight)."""
    inds = set()
    art = obj.get("artifacts", {}) or {}
    fav = art.get("favicon") or {}
    if fav.get("shodan_mmh3") is not None:
        v = f"favicon:{fav['shodan_mmh3']}"
        if not is_noise_indicator(v):
            inds.add(v)
    for label, vals in (art.get("trackers") or {}).items():
        for v in (vals if isinstance(vals, list) else [vals]):
            ind = f"{label}:{v}"
            if not is_noise_indicator(ind):
                inds.add(ind)
    for coin, vals in (art.get("crypto") or {}).items():
        for v in (vals if isinstance(vals, list) else [vals]):
            inds.add(f"wallet:{coin}:{v}")
    for label, vals in (art.get("saas_ids") or {}).items():
        for v in (vals if isinstance(vals, list) else [vals]):
            inds.add(f"saas:{label}:{v}")
    for label, tok in (art.get("verifications") or {}).items():
        inds.add(f"verification:{label}:{tok}")
    for net, handles in (art.get("socials") or {}).items():
        for h in (handles if isinstance(handles, list) else [handles]):
            # match ingest_webpivot's stored form (last path segment) so the reference.py
            # prevalence gate and case_index cross-lookup actually hit. NOTE: email/saas/qr/
            # verification keys still diverge from KB storage (email is an entity, not an
            # `email:` indicator) — reconcile those in a dedicated pass with a round-trip test.
            inds.add(f"social:{net}:{h.rstrip('/').split('/')[-1]}")
    for item in (art.get("qr_codes") or {}).get("payloads", []):
        inds.add(f"qr:{item.get('payload')}")
    for em in (art.get("emails") or []):
        if em and not is_noise_email(em):
            inds.add(f"email:{em.lower()}")
    # mail infrastructure (wp_recon.detect_mail_provider): M365 tenant, custom MX, SPF single hosts
    mail = art.get("mail") or {}
    if mail.get("m365_tenant"):
        inds.add(f"mail:m365:{str(mail['m365_tenant']).strip().lower()}")
    for ex in (mail.get("custom_mx_hosts") or []):
        ind = f"mail:mx:{str(ex).strip().lower().rstrip('.')}"
        if not is_noise_indicator(ind):
            inds.add(ind)
    spf = mail.get("spf") or {}
    for sip in (spf.get("ip4") or []) + (spf.get("ip6") or []):
        sip = str(sip).strip()
        if sip and ("/" not in sip or sip.split("/")[-1] in ("32", "128")):
            inds.add(f"mail:spf_ip:{sip.split('/')[0]}")
    return inds


def _current_state(case_dir):
    """Return (hosts:set, indicators:set) across all raw/*.json in the case."""
    hosts, inds = set(), set()
    for path in sorted(glob.glob(os.path.join(case_dir, "raw", "*.json"))):
        try:
            with open(path) as fh:
                obj = json.load(fh)
        except Exception:
            continue
        host = (obj.get("meta", {}) or {}).get("host") or os.path.basename(path)[:-5]
        if host:
            hosts.add(host)
        inds |= _indicators_from_raw(obj)
    return hosts, inds


def _rounds_path(case_dir):
    return os.path.join(case_dir, "rounds.jsonl")


def zero_growth(row):
    """A round counts as zero-growth only when nothing NEW showed up AND every host in the round
    was actually reachable. A round where a host errored (403/SSL/timeout/etc — recorded via
    `snapshot --failed`) must never read as convergence just because it also produced no new
    hosts/indicators; that is collection failure, not exhaustion of the estate. Rows written
    before `failed` existed have no such key at all — treat a missing key the same as an empty
    list so old rounds.jsonl files keep converging exactly as they always have."""
    return row.get("new_hosts", 0) == 0 and row.get("new_indicators", 0) == 0 and not row.get("failed")


def is_converged(rounds, stale):
    """CONVERGED = the last `stale` consecutive rounds are all zero_growth. Single source of
    truth: cmd_status here, case_state.convergence_verdict, and the harness orchestrator's
    _is_converged all call this instead of re-deriving the rule, so a failed-round exemption
    added in one place can never silently drift from the others."""
    return len(rounds) >= stale and all(zero_growth(r) for r in rounds[-stale:])


def _load_rounds(case_dir):
    p = _rounds_path(case_dir)
    if not os.path.exists(p):
        return []
    with open(p) as fh:
        return [json.loads(l) for l in fh if l.strip()]


def cmd_snapshot(args):
    cdir = _case_dir(args.case)
    if not os.path.isdir(cdir):
        print(f"no such case dir: {cdir}", file=sys.stderr)
        return 2
    hosts, inds = _current_state(cdir)
    rounds = _load_rounds(cdir)
    prev_hosts = set(rounds[-1]["host_set"]) if rounds else set()
    prev_inds = set(rounds[-1]["ind_set"]) if rounds else set()
    new_hosts = sorted(hosts - prev_hosts)
    new_inds = sorted(inds - prev_inds)
    failed_hosts = sorted({h.strip() for h in (getattr(args, "failed", "") or "").split(",") if h.strip()})
    snap = {"ts": _now(), "round": len(rounds) + 1,
            "hosts": len(hosts), "indicators": len(inds),
            "new_hosts": len(new_hosts), "new_indicators": len(new_inds),
            "host_set": sorted(hosts), "ind_set": sorted(inds), "failed": failed_hosts}
    with open(_rounds_path(cdir), "a") as fh:
        fh.write(json.dumps(snap, ensure_ascii=False) + "\n")
    print(f"round {snap['round']}: {snap['hosts']} hosts, {snap['indicators']} indicators "
          f"(+{snap['new_hosts']} hosts, +{snap['new_indicators']} indicators this round)")
    if new_hosts:
        print(f"  new hosts: {', '.join(new_hosts[:12])}{' …' if len(new_hosts) > 12 else ''}")
    if new_inds:
        print(f"  new indicators: {', '.join(new_inds[:8])}{' …' if len(new_inds) > 8 else ''}")
    if failed_hosts:
        print(f"  failed to collect: {', '.join(failed_hosts[:12])}{' …' if len(failed_hosts) > 12 else ''}"
              f" — this round cannot read as convergence")
    return 0


def cmd_status(args):
    cdir = _case_dir(args.case)
    rounds = _load_rounds(cdir)
    if not rounds:
        print(f"no snapshots yet for {args.case} — run: convergence.py snapshot {args.case}")
        return 0
    print(f"# Convergence — {args.case}   ({len(rounds)} rounds)\n")
    print(f"  {'round':>5}{'hosts':>7}{'+new':>6}{'indic':>7}{'+new':>6}   {'when'}")
    for r in rounds:
        print(f"  {r['round']:>5}{r['hosts']:>7}{r['new_hosts']:>6}{r['indicators']:>7}"
              f"{r['new_indicators']:>6}   {r['ts']}")
    stale = args.stale
    recent = rounds[-stale:]
    converged = is_converged(rounds, stale)
    recent_failed = sorted({h for r in recent for h in (r.get("failed") or [])})
    print()
    if converged:
        print(f"VERDICT: \033[32mCONVERGED\033[0m — last {stale} rounds added nothing new. "
              f"Stop pivoting; write the assessment.")
    elif len(rounds) < stale:
        print(f"VERDICT: \033[33mEXPANDING\033[0m — only {len(rounds)} round(s) so far; "
              f"need {stale} consecutive zero-growth rounds to call convergence.")
    elif recent_failed:
        print(f"VERDICT: \033[33mEXPANDING\033[0m — {len(recent_failed)} host(s) failed to "
              f"collect; retry before calling convergence "
              f"({', '.join(recent_failed[:8])}{' …' if len(recent_failed) > 8 else ''}).")
    else:
        win_h = sum(r["new_hosts"] for r in recent)
        win_i = sum(r["new_indicators"] for r in recent)
        print(f"VERDICT: \033[33mEXPANDING\033[0m — last {stale} rounds still added "
              f"+{win_h} hosts / +{win_i} indicators. Keep pivoting "
              f"(convergence = {stale} consecutive zero-growth rounds).")
    if args.budget_hosts and rounds[-1]["hosts"] >= args.budget_hosts:
        print(f"⚠ budget: {rounds[-1]['hosts']} hosts ≥ budget {args.budget_hosts} — "
              f"consider stopping or splitting the case.")
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    # `convergence <CASE>` (documented, dispatched by scripts/backend/intel.py) omits the
    # snapshot|status subcommand entirely — default it to `status` so a bare case id still works,
    # while `convergence snapshot <CASE>` / `convergence status <CASE>` keep working unchanged.
    if argv and argv[0] not in ("snapshot", "status", "-h", "--help"):
        argv = ["status", *argv]
    ap = argparse.ArgumentParser(description="Investigation stop-condition / convergence tracker")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("snapshot", help="record a round and report new growth")
    s.add_argument("case")
    s.add_argument("--failed", default="",
                   help="comma-separated hosts that FAILED to collect this round (live fetch "
                        "errored and no archive recovered it) — keeps the round from reading as "
                        "convergence even if it also added no new hosts/indicators")
    s.set_defaults(fn=cmd_snapshot)
    st = sub.add_parser("status", help="history + CONVERGED/EXPANDING verdict (default subcommand)")
    st.add_argument("case")
    st.add_argument("--stale", type=int, default=2,
                    help="# of consecutive zero-growth rounds that means converged (default 2)")
    st.add_argument("--budget-hosts", type=int, default=0, help="warn when host count hits this")
    st.set_defaults(fn=cmd_status)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
