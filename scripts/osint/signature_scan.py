#!/usr/bin/env python3
"""signature_scan.py — surface recurring behavioural signatures from analysis/signature-catalog.md.

Backs /signatures. The catalogue defines five families (TEMPORAL, BEHAVIORAL, NETWORK,
LINGUISTIC, AGENTIC) with thresholds — e.g. posting-interval variance <=3 min reads as automation.
Until now those thresholds lived only in prose, so the interpretation depended on whoever had read
the file most recently.

This parses the catalogue and evaluates the observations you supply against it. It DOES NOT
COLLECT: it has no way to observe posting cadence, and inventing one would be worse than useless.
Feed it what you already measured; it tells you which signature fires and what the catalogue says
that means.

AGENTIC family (AGT-01..AGT-09): autonomous / multi-agent attack tooling seen in captured attacker
telemetry or server logs. Supply raw events and the metrics are derived here:
  "requests": [{"ts": <epoch s|ms|ISO-8601>, "host", "path", "method", "status", "ua", "body"}]
  or parallel lists "request_timestamps", "hosts", "paths", "methods", "status_codes", "user_agents";
  "payloads" / "log_lines": [str]  (scanned for LLM prose and tool-call JSON);
  "credential_events": [{"ts", "kind": "exposed"|"attempt", "fingerprint": <hash, never the secret>,
                         "target"}].
Precomputed agt_* scalars (see --list) may be passed instead, e.g. --set agt_median_interval_ms=120.
A fired AGT signature identifies TOOLING (kit rung) — never the human operator or sponsor (RULE 5).
Tunables: scripts/osint/references/agentic_signatures.json.

Pure: reads the local catalogue. No network.

Usage:
  signature_scan.py --list
  signature_scan.py --set posting_interval_variance_min=2
  signature_scan.py observations.json --pretty
"""
# /// script
# requires-python = ">=3.9"
# ///
import argparse
import json
import os
import re
import statistics
import sys
from collections import defaultdict
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
CATALOG = os.path.join(REPO, "analysis", "signature-catalog.md")
WP = os.path.join(REPO, "intel_engine", "WebPivot", "tools")

# Observation key -> (signature id, family, evaluator, meaning). Thresholds mirror the catalogue;
# the catalogue text is quoted back so the two cannot silently diverge in interpretation.
RULES = [
    ("posting_interval_variance_min", "T-01", "TEMPORAL",
     lambda v: ("HIGH automation probability" if v <= 3 else
                "possible scheduler" if v <= 15 else "likely manual"),
     "variance in minutes between consecutive posts"),
    ("off_timezone_ratio", "T-02", "TEMPORAL",
     lambda v: ("activity clusters OUTSIDE the claimed timezone — the stated location is "
                "doubtful" if v >= 0.6 else "consistent with the claimed timezone"),
     "share of activity outside the subject's claimed working hours (0-1)"),
    ("accounts_posting_within_60s", "T-03", "TEMPORAL",
     lambda v: ("coordinated multi-account activity" if v >= 3 else
                "no coordination signal at this threshold"),
     "how many distinct accounts post the same content within 60s"),
    ("dormancy_days_before_burst", "T-04", "TEMPORAL",
     lambda v: ("dormancy-burst cycle — consistent with a held or resold account" if v >= 90
                else "no dormancy signal"),
     "days idle immediately before a burst of activity"),
    ("handle_leet_substitutions", "B-01", "BEHAVIORAL",
     lambda v: ("handle obfuscation — enumerate the variant space when pivoting" if v >= 1
                else "no substitution pattern"),
     "count of leet/homoglyph substitutions in the handle"),
    ("platforms_present", "B-02", "BEHAVIORAL",
     lambda v: ("broad platform footprint — a persona maintained deliberately" if v >= 5 else
                "narrow footprint — consistent with a single-purpose or disposable account"),
     "number of platforms the handle resolves on"),
    ("follower_to_following_ratio", "N-01", "NETWORK",
     lambda v: ("inorganic follower graph — bought or farmed" if v <= 0.1 else
                "unremarkable follower structure"),
     "followers divided by following"),
    ("shared_phrase_accounts", "N-02", "NETWORK",
     lambda v: ("coordinated messaging — the same phrasing across accounts" if v >= 3 else
                "no coordination signal"),
     "accounts sharing a distinctive phrase verbatim"),
]

# ── AGENTIC family ──────────────────────────────────────────────────────────────────────────────
# Tunables are reference DATA (references/agentic_signatures.json). Fallback = conservative minimum.
_AGT_FALLBACK = {
    "thresholds": {"cadence_min_requests": 50, "cadence_median_interval_ms": 1000,
                   "burst_interval_ms": 1000, "burst_min_requests": 5, "planner_gap_min_s": 1.5,
                   "planner_gap_max_s": 60, "planner_min_bursts": 3, "fanout_window_s": 10,
                   "fanout_min_hosts": 10, "enumeration_min_items": 20,
                   "enumeration_ordered_ratio": 0.85, "library_ua_share": 0.5,
                   "ua_mix_min_share": 0.05, "retry_window_s": 10, "retry_min_variations": 3,
                   "llm_artefact_min_hits": 1, "tool_call_min_hits": 1,
                   "harvest_to_spray_max_min": 60},
    "library_user_agents": ["python-httpx", "python-requests", "aiohttp", "go-http-client",
                            "node-fetch", "undici", "^curl/"],
    "headless_user_agents": ["headlesschrome", "puppeteer", "playwright", "selenium"],
    "declared_agent_user_agents": ["gptbot", "chatgpt-user", "claudebot", "perplexitybot"],
    "llm_artefact_patterns": ["as an ai( language)? model", "<thinking>|</thinking>"],
    "tool_call_patterns": ["\"tool_calls\"\\s*:", "\"function_call\"\\s*:", "\"tool_use\""],
}

AGT_RUNG = "kit"
AGT_CAVEAT = ("RULE 5: an AGENTIC signature identifies TOOLING (kit rung) — an agent framework or "
              "automation harness — never the human operator or sponsor. Record it as a FACT/LEAD "
              "on the traffic, never a KB edge, never operator_lead; CI pipelines, scanners and "
              "legitimate automation produce the same shapes.")


def _load_agt_refs():
    try:
        if WP not in sys.path:
            sys.path.insert(0, WP)
        from wp_refs import load_ref, ref_path  # noqa: E402
        return load_ref(ref_path(__file__, "agentic_signatures.json"), _AGT_FALLBACK)
    except Exception:  # noqa: BLE001 — loader missing: the conservative minimum, loudly
        print("[!] agentic_signatures.json not loaded — using the embedded minimum", file=sys.stderr)
        return dict(_AGT_FALLBACK)


def _rx(patterns):
    out = []
    for p in patterns or []:
        try:
            out.append(re.compile(p, re.I | re.M))
        except re.error as exc:
            print(f"[!] agentic_signatures.json: bad regex {p!r} ({exc}) — skipped", file=sys.stderr)
    return out


# Raw AGENTIC inputs (not scalar observations — consumed by derive_agentic, never "unknown").
AGT_RAW_KEYS = {"requests", "request_timestamps", "hosts", "paths", "methods", "status_codes",
                "user_agents", "payloads", "log_lines", "credential_events"}


def _ts(v):
    """Epoch seconds (float) from epoch s / epoch ms / ISO-8601; None when unparseable."""
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v) / 1000.0 if v > 1e12 else float(v)
    try:
        return datetime.fromisoformat(str(v).strip().replace("Z", "+00:00")).timestamp()
    except ValueError:
        try:
            return _ts(float(v))
        except ValueError:
            return None


def _template(path):
    """Path shape without query and with ids collapsed — '/api/u/42?x=1' -> '/api/u/{n}'."""
    p = str(path or "").split("?", 1)[0].split("#", 1)[0]
    p = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "{uuid}", p, flags=re.I)
    p = re.sub(r"\b[0-9a-f]{12,}\b", "{h}", p, flags=re.I)
    return re.sub(r"\d+", "{n}", p)


def _requests(obs):
    """Normalise either input shape into a time-sorted list of request dicts."""
    reqs = []
    if isinstance(obs.get("requests"), list):
        for r in obs["requests"]:
            if isinstance(r, dict):
                reqs.append({"ts": _ts(r.get("ts", r.get("timestamp"))),
                             "host": str(r.get("host") or ""), "path": str(r.get("path") or ""),
                             "method": str(r.get("method") or "GET").upper(),
                             "status": r.get("status"), "ua": str(r.get("ua") or r.get("user_agent") or ""),
                             "body": str(r.get("body") or "")})
    else:
        cols = {k: obs.get(k) if isinstance(obs.get(k), list) else []
                for k in ("request_timestamps", "hosts", "paths", "methods", "status_codes",
                          "user_agents")}
        n = max((len(v) for v in cols.values()), default=0)
        at = lambda k, i, d="": cols[k][i] if i < len(cols[k]) else d  # noqa: E731
        for i in range(n):
            reqs.append({"ts": _ts(at("request_timestamps", i, None)), "host": str(at("hosts", i)),
                         "path": str(at("paths", i)), "method": str(at("methods", i) or "GET").upper(),
                         "status": at("status_codes", i, None), "ua": str(at("user_agents", i)),
                         "body": ""})
    timed = [r for r in reqs if r["ts"] is not None]
    timed.sort(key=lambda r: r["ts"])
    return reqs, timed


def _status(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def derive_agentic(obs, refs):
    """Raw events -> agt_* scalar metrics (+ evidence notes). Only metrics whose inputs exist."""
    T = refs["thresholds"]
    m, ev = {}, {}
    reqs, timed = _requests(obs)
    if reqs:
        m["agt_request_count"] = len(reqs)

    # AGT-01 / AGT-02: cadence and planner/worker bursts.
    if len(timed) >= 2:
        iv = [(b["ts"] - a["ts"]) * 1000.0 for a, b in zip(timed, timed[1:])]
        m["agt_median_interval_ms"] = round(statistics.median(iv), 1)
        burst_ms, bmin = T["burst_interval_ms"], T["burst_min_requests"]
        gmin, gmax = T["planner_gap_min_s"] * 1000.0, T["planner_gap_max_s"] * 1000.0
        bursts, run, gap_before = 0, 1, None
        for x in iv + [float("inf")]:
            if x < burst_ms:
                run += 1
                continue
            if run >= bmin and (gap_before is None or gmin <= gap_before <= gmax):
                bursts += 1
            run, gap_before = 1, x
        m["agt_planner_bursts"] = bursts

    # AGT-03: one path template hit on many distinct hosts inside a short window.
    if timed and any(r["host"] for r in timed):
        by_tpl = defaultdict(list)
        for r in timed:
            if r["host"]:
                by_tpl[(r["method"], _template(r["path"]))].append(r)
        win, best, best_tpl = T["fanout_window_s"], 0, None
        for tpl, rs in by_tpl.items():
            cnt, lo = defaultdict(int), 0
            for hi, r in enumerate(rs):
                cnt[r["host"]] += 1
                while rs[hi]["ts"] - rs[lo]["ts"] > win:
                    cnt[rs[lo]["host"]] -= 1
                    if not cnt[rs[lo]["host"]]:
                        del cnt[rs[lo]["host"]]
                    lo += 1
                if len(cnt) > best:
                    best, best_tpl = len(cnt), tpl
        m["agt_fanout_hosts"] = best
        if best_tpl:
            ev["fanout_template"] = f"{best_tpl[0]} {best_tpl[1]}"

    # AGT-04: systematic enumeration — lexicographic or +1 numeric ordering of distinct targets.
    seq = []
    for r in timed:
        key = f"{r['host']}{r['path']}"
        if key and (not seq or seq[-1] != key):
            seq.append(key)
    if seq:
        m["agt_distinct_ordered_items"] = len(set(seq))
        if len(seq) >= 2:
            pairs = list(zip(seq, seq[1:]))
            asc = sum(1 for a, b in pairs if a < b) / len(pairs)

            def lastnum(s):
                f = re.findall(r"\d+", s)
                return int(f[-1]) if f else None
            inc = sum(1 for a, b in pairs if lastnum(a) is not None and lastnum(b) is not None
                      and lastnum(b) - lastnum(a) == 1 and _template(a) == _template(b)) / len(pairs)
            m["agt_enumeration_ordered_ratio"] = round(max(asc, inc), 3)
            ev["enumeration_mode"] = "numeric +1" if inc > asc else "lexicographic"

    # AGT-05: default library UAs, mixed with headless browsers / declared agent fetchers.
    uas = [r["ua"] for r in reqs if r["ua"]]
    if uas:
        lib, hdl, dec = (_rx(refs[k]) for k in ("library_user_agents", "headless_user_agents",
                                                "declared_agent_user_agents"))
        share = lambda rxs: sum(1 for u in uas if any(x.search(u) for x in rxs)) / len(uas)  # noqa: E731
        m["agt_library_ua_share"] = round(share(lib), 3)
        m["agt_headless_ua_share"] = round(share(hdl), 3)
        m["agt_declared_agent_ua_share"] = round(share(dec), 3)
        ev["distinct_user_agents"] = len(set(uas))

    # AGT-06: retry-with-variation after a 4xx on the same host + path template.
    if timed and any(_status(r["status"]) is not None for r in timed):
        nxt, variations, hosts = {}, 0, set()
        for i in range(len(timed) - 1, -1, -1):          # walk backwards: next same-shape request
            r = timed[i]
            k = (r["host"], _template(r["path"]))
            s = _status(r["status"])
            n = nxt.get(k)
            if (s is not None and 400 <= s < 500 and n is not None
                    and n["ts"] - r["ts"] <= T["retry_window_s"]
                    and (n["path"], n["method"], n["body"]) != (r["path"], r["method"], r["body"])):
                variations += 1
                hosts.add(r["host"])
            nxt[k] = r
        m["agt_retry_variations"] = variations
        ev["retry_variation_hosts"] = len(hosts)

    # AGT-07 / AGT-08: LLM prose and tool-call JSON in payloads, bodies, UAs and log lines.
    texts = [r["body"] for r in reqs if r["body"]] + uas
    for k in ("payloads", "log_lines"):
        if isinstance(obs.get(k), list):
            texts += [str(t) for t in obs[k] if t]
    if texts:
        for key, ref, evk in (("agt_llm_artefact_hits", "llm_artefact_patterns", "llm_patterns"),
                              ("agt_tool_call_hits", "tool_call_patterns", "tool_call_patterns")):
            rxs = _rx(refs[ref])
            hit = [x.pattern for x in rxs if any(x.search(t) for t in texts)]
            m[key] = sum(1 for t in texts if any(x.search(t) for x in rxs))
            if hit:
                ev[evk] = hit[:8]

    # AGT-09: secret exposed publicly, then sprayed minutes later (fingerprints only).
    ce = obs.get("credential_events")
    if isinstance(ce, list) and ce:
        exposed, attempts = {}, defaultdict(list)
        for e in ce:
            if not isinstance(e, dict) or not e.get("fingerprint"):
                continue
            t = _ts(e.get("ts"))
            if t is None:
                continue
            fp, kind = str(e["fingerprint"]), str(e.get("kind") or "").lower()
            if kind == "exposed":
                exposed[fp] = min(t, exposed.get(fp, t))
            elif kind == "attempt":
                attempts[fp].append((t, str(e.get("target") or "")))
        lags, targets = [], set()
        for fp, at in attempts.items():
            if fp in exposed:
                after = [(t, tg) for t, tg in at if t >= exposed[fp]]
                if after:
                    lags.append((min(t for t, _ in after) - exposed[fp]) / 60.0)
                    targets.update(tg for _, tg in after if tg)
        if lags:
            m["agt_harvest_to_spray_min"] = round(min(lags), 1)
            ev["sprayed_fingerprints"] = len(lags)
            ev["spray_targets"] = len(targets)
    return m, ev


# (signature id, title, primary metric, evaluator(metrics, thresholds) -> (fired, interpretation)).
# Thresholds mirror the catalogue's AGENTIC_SIGNATURES section and live in agentic_signatures.json.
AGT_RULES = [
    ("AGT-01", "Sub-second machine cadence", "agt_median_interval_ms",
     lambda m, T: (m.get("agt_median_interval_ms", 1e9) <= T["cadence_median_interval_ms"]
                   and m.get("agt_request_count", T["cadence_min_requests"]) >= T["cadence_min_requests"],
                   f"median inter-request interval {m['agt_median_interval_ms']} ms over "
                   f"{m.get('agt_request_count', '?')} requests (fires at <= "
                   f"{T['cadence_median_interval_ms']} ms and >= {T['cadence_min_requests']} requests)")),
    ("AGT-02", "Planner/worker burst rhythm", "agt_planner_bursts",
     lambda m, T: (m["agt_planner_bursts"] >= T["planner_min_bursts"],
                   f"{m['agt_planner_bursts']} sub-second worker bursts separated by "
                   f"{T['planner_gap_min_s']}-{T['planner_gap_max_s']} s planning pauses (fires at >= "
                   f"{T['planner_min_bursts']})")),
    ("AGT-03", "Parallel fan-out across hosts", "agt_fanout_hosts",
     lambda m, T: (m["agt_fanout_hosts"] >= T["fanout_min_hosts"],
                   f"one request shape hit {m['agt_fanout_hosts']} distinct hosts within "
                   f"{T['fanout_window_s']} s (fires at >= {T['fanout_min_hosts']})")),
    ("AGT-04", "Systematic enumeration ordering", "agt_enumeration_ordered_ratio",
     lambda m, T: (m["agt_enumeration_ordered_ratio"] >= T["enumeration_ordered_ratio"]
                   and m.get("agt_distinct_ordered_items", T["enumeration_min_items"])
                   >= T["enumeration_min_items"],
                   f"{m['agt_enumeration_ordered_ratio']:.0%} of consecutive targets in sorted / +1 "
                   f"order over {m.get('agt_distinct_ordered_items', '?')} distinct targets (fires at "
                   f">= {T['enumeration_ordered_ratio']:.0%} and >= {T['enumeration_min_items']})")),
    ("AGT-05", "Library / headless user-agent mix", "agt_library_ua_share",
     lambda m, T: (m["agt_library_ua_share"] >= T["library_ua_share"]
                   or (m["agt_library_ua_share"] >= T["ua_mix_min_share"]
                       and max(m.get("agt_headless_ua_share", 0),
                               m.get("agt_declared_agent_ua_share", 0)) >= T["ua_mix_min_share"]),
                   f"default-library UA share {m['agt_library_ua_share']:.0%}, headless "
                   f"{m.get('agt_headless_ua_share', 0):.0%}, declared-agent "
                   f"{m.get('agt_declared_agent_ua_share', 0):.0%} (fires at library >= "
                   f"{T['library_ua_share']:.0%}, or library + headless/agent each >= "
                   f"{T['ua_mix_min_share']:.0%})")),
    ("AGT-06", "Retry-with-variation after 4xx", "agt_retry_variations",
     lambda m, T: (m["agt_retry_variations"] >= T["retry_min_variations"],
                   f"{m['agt_retry_variations']} 4xx responses followed within "
                   f"{T['retry_window_s']} s by a VARIED request to the same host+path shape "
                   f"(fires at >= {T['retry_min_variations']})")),
    ("AGT-07", "LLM prose artefacts in traffic", "agt_llm_artefact_hits",
     lambda m, T: (m["agt_llm_artefact_hits"] >= T["llm_artefact_min_hits"],
                   f"{m['agt_llm_artefact_hits']} payload/log/UA strings carry assistant-style prose "
                   f"(fires at >= {T['llm_artefact_min_hits']})")),
    ("AGT-08", "Tool-call JSON / prompt leakage", "agt_tool_call_hits",
     lambda m, T: (m["agt_tool_call_hits"] >= T["tool_call_min_hits"],
                   f"{m['agt_tool_call_hits']} payload/log strings carry tool-call or agent-protocol "
                   f"fragments (fires at >= {T['tool_call_min_hits']})")),
    ("AGT-09", "Fresh-harvest credential spraying", "agt_harvest_to_spray_min",
     lambda m, T: (m["agt_harvest_to_spray_min"] <= T["harvest_to_spray_max_min"],
                   f"a publicly exposed secret was first tried {m['agt_harvest_to_spray_min']} min "
                   f"after exposure (fires at <= {T['harvest_to_spray_max_min']} min)")),
]

AGT_SCALAR_KEYS = {"agt_request_count", "agt_median_interval_ms", "agt_planner_bursts",
                   "agt_fanout_hosts", "agt_distinct_ordered_items", "agt_enumeration_ordered_ratio",
                   "agt_library_ua_share", "agt_headless_ua_share", "agt_declared_agent_ua_share",
                   "agt_retry_variations", "agt_llm_artefact_hits", "agt_tool_call_hits",
                   "agt_harvest_to_spray_min"}


def evaluate_agentic(obs):
    """-> (fired rows, quiet rows, derived block | None)."""
    if not (AGT_RAW_KEYS | AGT_SCALAR_KEYS) & set(obs):
        return [], [], None
    refs = _load_agt_refs()
    T = {**_AGT_FALLBACK["thresholds"], **(refs.get("thresholds") or {})}
    metrics, evidence = derive_agentic(obs, refs)
    for k in AGT_SCALAR_KEYS:                      # analyst-supplied scalars win over derived ones
        if k in obs:
            try:
                metrics[k] = float(obs[k])
            except (TypeError, ValueError):
                pass
    fired, quiet = [], []
    for sid, title, key, ev in AGT_RULES:
        if key not in metrics:
            continue
        hit, why = ev(metrics, T)
        row = {"signature": sid, "family": "AGENTIC", "title": title, "observation": key,
               "value": metrics[key], "interpretation": why, "rung": AGT_RUNG}
        if hit:
            row["caveat"] = AGT_CAVEAT
        (fired if hit else quiet).append(row)
    return fired, quiet, {"metrics": metrics, "evidence": evidence, "rung": AGT_RUNG,
                          "caveat": AGT_CAVEAT}


def catalog_families():
    if not os.path.isfile(CATALOG):
        return {"status": f"catalogue not found at {CATALOG}"}
    txt = open(CATALOG, encoding="utf-8").read()
    fams = re.findall(r"^## ([A-Z_]+_SIGNATURES)$", txt, re.M)
    ids = re.findall(r"^### ([A-Z]+-\d+): (.+)$", txt, re.M)
    return {"status": "ok", "families": fams,
            "signatures": [{"id": i, "title": t.strip()} for i, t in ids],
            "path": os.path.relpath(CATALOG, REPO)}


def main():
    ap = argparse.ArgumentParser(description="Evaluate observations against the signature catalogue.")
    ap.add_argument("infile", nargs="?", help="JSON of {observation: value}")
    ap.add_argument("--set", action="append", default=[], metavar="KEY=VALUE")
    ap.add_argument("--list", action="store_true", help="show the catalogue and the inputs it takes")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    if a.list:
        cat = catalog_families()
        print(json.dumps({"catalog": cat,
                          "accepted_observations": [
                              {"key": k, "signature": sid, "family": fam, "means": desc}
                              for k, sid, fam, _, desc in RULES] + [
                              {"key": key, "signature": sid, "family": "AGENTIC", "means": title}
                              for sid, title, key, _ in AGT_RULES],
                          "agentic_raw_inputs": sorted(AGT_RAW_KEYS),
                          "agentic_scalar_overrides": sorted(AGT_SCALAR_KEYS)},
                         indent=2, ensure_ascii=False))
        return 0

    obs = {}
    if a.infile:
        obs.update(json.load(open(a.infile, encoding="utf-8")))
    for kv in a.set:
        if "=" not in kv:
            ap.error(f"--set expects KEY=VALUE, got {kv!r}")
        k, v = kv.split("=", 1)
        try:
            obs[k.strip()] = float(v)
        except ValueError:
            ap.error(f"--set value must be numeric: {kv!r}")

    known = {k for k, *_ in RULES} | AGT_RAW_KEYS | AGT_SCALAR_KEYS
    fired, quiet = [], []
    for key, sid, fam, ev, desc in RULES:
        if key not in obs:
            continue
        if not isinstance(obs[key], (int, float)) or isinstance(obs[key], bool):
            continue
        verdict = ev(obs[key])
        row = {"signature": sid, "family": fam, "observation": key,
               "value": obs[key], "interpretation": verdict}
        (fired if verdict.lower().startswith(("high", "coordinated", "inorganic", "dormancy",
                                              "handle obfuscation", "activity clusters",
                                              "broad", "possible")) else quiet).append(row)
    agt_fired, agt_quiet, agentic = evaluate_agentic(obs)
    fired += agt_fired
    quiet += agt_quiet

    out = {"catalog": catalog_families(), "fired": fired, "quiet": quiet,
           "evaluated": len(fired) + len(quiet),
           "ignored_unknown": sorted(set(obs) - known),
           "not_collected": ("This tool does NOT observe behaviour — it has no way to measure "
                             "posting cadence or follower graphs, and guessing them would be "
                             "worse than useless. Supply observations you actually measured."),
           "caveat": ("A fired signature is a HYPOTHESIS about behaviour, not an identification. "
                      "Automation, coordination and a bought follower graph are all consistent "
                      "with ordinary marketing as well as with fraud.")}
    if agentic is not None:
        out["agentic"] = agentic
    if not out["evaluated"]:
        out["verdict"] = "no recognised observations supplied — nothing evaluated"
    else:
        out["verdict"] = f"{len(fired)} signature(s) fired of {out['evaluated']} evaluated"
    print(f"signatures: {len(fired)} fired / {out['evaluated']} evaluated", file=sys.stderr)
    for f in fired:
        print(f"  {f['signature']} [{f['family']}] {f['observation']}={f['value']} → "
              f"{f['interpretation']}", file=sys.stderr)
    txt = json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)
    print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
