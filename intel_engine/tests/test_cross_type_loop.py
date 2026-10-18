#!/usr/bin/env python3
"""Cross-type loop — offline end-to-end fixture over the REAL harness loop (orchestrator.run_case).

A synthetic estate reached from ONE e-mail seed, across types:

    ops@operator.example ──rwhois purchase (APPROVED)──► alpha / beta / gamma.example   (owner)
    beta's wallet ──urlscan identifier──► delta.example (owner) + shared-neighbour.example (neighbour)
    alpha's GTM id ──urlscan identifier──► zeta.example (owner)
    planner hunch: kit filename vk_pay_v2.js ──urlscan filename──► epsilon + unrelated-shop (kit)
    beta's wallet ──Wayback telegram──► @op_channel (kit node) + a news MENTION
    beta's wallet ──counterparties (APPROVED)──► an exchange wallet (neighbour)
    analyst seed `invoice.zip` — a FILENAME, never a host

What it defends (consumer-visible rails, not wiring):
  * recall: every owner host is reached and attributed; kit/neighbour hosts are COLLECTED;
  * collecting ≠ attributing: kit/neighbour hosts never reach the judged partition or
    Assessment.cluster even when the judge (deliberately naive here) lists them and the legacy
    ingest links them by a shared favicon — they land in kit_siblings / neighbours / tiers.json;
  * spend: no metered pivot runs before the analyst approves it; an unapproved metered call made
    during the loop is DENIED by audit.gate; a no_spend scope never even previews reverse-WHOIS;
  * a filename seed is never collected, never WHOIS'd, never a domain candidate;
  * planner additions are validated (unknown route / filename-as-domain refused);
  * gate boundaries: est_hits N → auto, N+1 / unknown → proposal; a stale digest is refused;
    case_approve is denied from any harness phase.
Stubs: the LLM phases, the corpus network (pivot_routes.run/count), reverse-WHOIS preview.
Needs claude_agent_sdk (orchestrator import): run with the skill venv.
"""
import asyncio
import json
import os
import shutil
import sys
import tempfile
from types import SimpleNamespace as NS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "harness"))

CASE, CASE_NS = "_XTYPE_TEST_CASE", "_XTYPE_TEST_NOSPEND"
EMAIL = "ops@operator.example"
WALLET, EXCH = "0x" + "ab" * 20, "0x" + "cd" * 20
GTM, KITFILE = "GTM-XXXX01", "vk_pay_v2.js"
OWNERS = {"alpha.example", "beta.example", "gamma.example", "delta.example", "zeta.example"}
KIT = {"epsilon.example", "unrelated-shop.example"}
NEIGHBOUR = {"shared-neighbour.example"}
KEEP_ROUTES = {"collect", "rwhois.purchase", "urlscan.identifier", "urlscan.filename",
               "wayback.telegram", "crypto.counterparties"}
METERED_ROUTES = {"rwhois.purchase", "fofa.body", "publicwww.source", "email.deep", "anyrun.lookup"}


def _raw(host):
    managed, self_ns = ["ns1.managed-dns.example", "ns2.managed-dns.example"], ["ns1.alpha.example"]
    spec = {  # registrant / NS variant / GTM / wallet / favicon — the shared favicon is the trap
        "alpha.example": (EMAIL, managed, True, False, "777"),
        "beta.example": (EMAIL, self_ns, False, True, "111"),
        "gamma.example": (EMAIL, managed, False, False, "777"),
        "delta.example": (None, managed, False, True, "222"),
        "zeta.example": (None, self_ns, True, False, "333"),
        "epsilon.example": (None, managed, False, False, "444"),
        "unrelated-shop.example": (None, managed, False, False, "777"),
        "shared-neighbour.example": (None, managed, False, False, "777"),
    }[host]
    reg, ns, gtm, wallet, fav = spec
    whois = {"domain": host, "registrar": "Example Registrar LLC", "name_servers": ns,
             "created": "2026-01-01T00:00:00Z", "source": "rdap"}
    if reg:
        whois["registrant_email"] = reg
    art = {"title": host, "http": {"status": "200"},
           "favicon": {"shodan_mmh3": fav, "md5": fav * 4}, "whois": whois,
           "trackers": {"google_tag_manager": [GTM]} if gtm else {},
           "crypto": {"eth": [WALLET]} if wallet else {}}
    return {"meta": {"host": host, "final_url": f"https://{host}/",
                     "collected_at": "2026-01-01T00:00:00Z"}, "artifacts": art, "pivots": []}


def _corpus(route, query):
    """The synthetic corpus every pivot route answers from (pivot_routes.run stub)."""
    q = query or ""
    if route == "rwhois.purchase" and EMAIL in q:
        return [{"type": "domain", "value": d, "rung_class": "whois.registrant_email", "source": route}
                for d in ("alpha.example", "beta.example", "gamma.example")]
    if route == "urlscan.identifier" and WALLET in q:
        return [{"type": "domain", "value": "delta.example", "rung_class": "wallet.operator", "source": route},
                {"type": "domain", "value": "shared-neighbour.example", "rung_class": "ip.cotenant",
                 "source": route}]
    if route == "urlscan.identifier" and GTM.replace("-", "\\-") in q or (route == "urlscan.identifier" and GTM in q):
        return [{"type": "domain", "value": "zeta.example", "rung_class": "analytics.gtm", "source": route}]
    if route == "urlscan.filename" and KITFILE.replace(".", "") in q.replace(".", "").replace("\\", ""):
        return [{"type": "domain", "value": d, "rung_class": "filename", "source": route}
                for d in sorted(KIT)]
    if route == "wayback.telegram" and WALLET in q:
        return [{"type": "telegram", "value": "op_channel", "rung_class": "telegram.username",
                 "source": route, "evidence": {"url": "https://t.me/s/op_channel/1"}},
                {"type": "mention", "value": "https://news.example/story", "rung_class": "string",
                 "source": "wayback.news"}]
    if route == "crypto.counterparties" and WALLET in q:
        return [{"type": "wallet", "value": EXCH, "rung_class": "wallet.exchange", "source": route,
                 "coin": "eth"}]
    return []


def check():
    passed = failed = 0
    out = []

    def ok(cond, label):
        nonlocal passed, failed
        passed, failed = (passed + 1, failed) if cond else (passed, failed + 1)
        out.append(("ok" if cond else "FAIL", label))

    import orchestrator as O  # noqa: E402 — pulls the SDK
    import tools as T  # noqa: E402
    import case_state as cs  # noqa: E402
    import pivot_routes as PR  # noqa: E402
    import proposal as P  # noqa: E402
    import audit  # noqa: E402
    import case_scope  # noqa: E402
    from schemas import Assessment  # noqa: E402
    from knowledge_base import KB  # noqa: E402
    kbdir = tempfile.mkdtemp(prefix="xtype-kb-")
    log = {"run": [], "collect_seeds": [], "rw_modes": [], "stops": [], "gate_in_loop": [],
           "plan_adds": 0, "counts": [], "flaky": True, "veto": False, "case": None}

    def fake_run(route, query, *, case="", free_only=False, hostile=False):
        log["run"].append((route, query))
        if route == "wayback.telegram" and log["flaky"]:   # one transient corpus failure
            log["flaky"] = False
            return {"error": "HTTP 503 Temporarily Offline"}
        rows = _corpus(route, query)
        return {"rows": rows, "total": len(rows)}

    def fake_count(route, query, *, free_only=False):
        """count_probe semantics: urlscan/wayback return a known total, everything else unknown."""
        log["counts"].append((log["case"], route, bool(free_only)))
        if route.startswith(("urlscan.", "wayback.")):
            return len(_corpus(route, query))
        return None

    async def fake_phase(prompt, *, label, **kw):
        if label == "collect":
            log.setdefault("collect_loop", []).append(
                (kw["case"], P.loop_active(P.load(O.ROOT, kw["case"]))))
            if not log["gate_in_loop"]:          # an unapproved metered pivot DURING the loop
                log["gate_in_loop"].append(audit.decide(
                    "corpus_search", {"route": "fofa.body", "query": 'body="x"', "case": kw["case"]},
                    case=kw["case"], phase="collect")[0])
            for line in prompt.splitlines():
                h = line[2:].strip() if line.startswith("- ") else ""
                if h:
                    log["collect_seeds"].append(h)
                    try:
                        raw = _raw(h)
                    except KeyError:
                        continue
                    os.makedirs(os.path.join(O.ROOT, "cases", kw["case"], "raw"), exist_ok=True)
                    with open(os.path.join(O.ROOT, "cases", kw["case"], "raw", h + ".json"), "w") as fh:
                        json.dump(raw, fh)
            T.ingest(kw["case"])
            return NS(session_id="C", subtype="success", structured_output=None)
        if label in ("correlate", "verify"):
            return NS(session_id="S", subtype="success", structured_output=None)
        if label.startswith("assess"):
            hosts = sorted(cs.collected_hosts(os.path.join(O.ROOT, "cases", kw["case"])))
            a = Assessment(decision_supported="who runs the estate", bluf="likely one operator",
                           cluster=[{"domain": h, "shared_artifacts": ["favicon:777"]} for h in hosts],
                           attribution_level="same-operator", confidence="moderate")
            return NS(session_id="S", subtype="success", structured_output=a.model_dump())
        if label == "plan":
            ranked, dropped = [], []
            if log["veto"]:                         # a planner that vetoes the whole frontier
                ids = [ln.split(" | ")[0].strip() for ln in prompt.splitlines()
                       if len(ln.split(" | ")) >= 7 and not ln.startswith("id ")]
                return NS(session_id="P", subtype="success", structured_output={
                    "ranked": [], "added": [], "notes": "veto",
                    "dropped": [{"id": i, "why": "veto"} for i in ids]})
            for line in prompt.splitlines():
                parts = [p.strip() for p in line.split(" | ")]
                if len(parts) < 7 or parts[0] == "id":
                    continue
                cid, route, rung = parts[0], parts[3], parts[6]
                if route not in KEEP_ROUTES or (route == "crypto.counterparties" and rung == "neighbour"):
                    dropped.append({"id": cid, "why": "fixture planner: off-plan route"})
                else:
                    ranked.append(cid)
            log["plan_adds"] += 1
            added = [{"type": "filename", "selector": KITFILE, "tool": "urlscan.filename",
                      "why": "kit script seen on owned hosts"},
                     {"type": "domain", "selector": "invoice.zip", "tool": "collect",
                      "why": "a filename the planner mistook for a host"},
                     {"type": "string", "selector": "kit phrase", "tool": "nope.route",
                      "why": "a route that does not exist"}]
            return NS(session_id="P", subtype="success",
                      structured_output={"ranked": ranked, "dropped": dropped, "added": added,
                                         "notes": "fixture"})
        raise AssertionError(f"unexpected phase {label}")

    names = ("_phase", "_skill", "_binary_round", "_domain_table", "_persist_assessment",
             "_report_cost", "_convergence_snapshot", "_is_converged", "_hand_back",
             "_discover_new_seeds", "_discovered_infra_seeds", "_case_registrant_terms", "_rw_call",
             "VERIFY_ON", "ESCALATE_ON")
    saved = {n: getattr(O, n) for n in names}
    saved_mod = (T.KB_DIR, cs.KB_DIR, PR.run, PR.count, dict(O._SCOPE_CACHE))
    # SANDBOX ENGINE ROOT: symlinks to the real code + an empty cases/ — every module that builds
    # cases/<id>/… paths is pointed here, so nothing lands in the real intel_engine/cases/.
    sandbox = tempfile.mkdtemp(prefix="xtype-root-")
    for name in os.listdir(O.ROOT):
        if name not in ("cases", "knowledge"):
            os.symlink(os.path.join(O.ROOT, name), os.path.join(sandbox, name))
    os.makedirs(os.path.join(sandbox, "cases"))
    roots = [(O, "ROOT"), (T, "ROOT"), (cs, "ROOT"), (audit, "ROOT"), (case_scope, "ROOT"),
             (PR, "_ENGINE")]
    saved_roots = [(m, a, getattr(m, a)) for m, a in roots]
    try:
        for m, a in roots:
            setattr(m, a, sandbox)
        T.KB_DIR = cs.KB_DIR = kbdir
        PR.run, PR.count = fake_run, fake_count
        O._phase, O._skill = fake_phase, (lambda name: "")
        O._binary_round = lambda *a, **k: None
        O._domain_table = lambda case_: ""
        O._persist_assessment = lambda a, case_, t: {"round": 0, "snapshot_md": "", "summary": ""}
        O._report_cost = lambda *a, **k: None
        O._convergence_snapshot = lambda case_, **k: ""
        O._is_converged = lambda case_, stale: False
        real_hand_back = saved["_hand_back"]     # REAL hand-back: it rewrites state.json after the
        O._hand_back = lambda case_, stop, **k: (log["stops"].append(stop),      # proposal is written
                                                  real_hand_back(case_, stop, **k))[0]
        O._discover_new_seeds = lambda *a, **k: []
        O._discovered_infra_seeds = lambda *a, **k: {}
        O._case_registrant_terms = lambda case_: [("email", EMAIL)]
        O._rw_call = lambda flag, term, mode: (log["rw_modes"].append(mode) or {"count": 3})
        O.VERIFY_ON = O.ESCALATE_ON = False
        O._SCOPE_CACHE[CASE] = case_scope.resolve(CASE, root=sandbox, persist=False)

        def run(seeds, case=CASE):
            log["case"] = case
            try:
                res = asyncio.run(O.run_case(seeds, case, hostile=False, depth=6, stale=2, max_new=8))
                if res is not None:
                    log["final"] = res              # the latest judgment the loop produced
                return res
            except RuntimeError as e:          # surfaces as failed assertions, not a crash
                log["stops"].append(f"error: {e}")
                return None

        def metered_runs():
            return [r for r, _q in log["run"] if r in METERED_ROUTES or r == "crypto.counterparties"]

        # ---- run 1: e-mail + filename seeds → stops for approval, nothing metered spent -------
        run([EMAIL, "invoice.zip"])
        prop = P.load(O.ROOT, CASE) or {}
        rw = [i for i in prop.get("items") or [] if i.get("tool") == "rwhois.purchase"]
        ok(log["stops"][-1] == "awaiting-approval" and rw
           and cs.load_state(CASE).get("status") == "awaiting-approval",
           "run 1 stops at awaiting-approval (state.json says so) with the purchase proposed")
        ok(not metered_runs() and set(log["rw_modes"]) == {"preview"},
           "nothing metered ran before approval (reverse-WHOIS previewed only)")
        ok(not any(i.get("type") == "domain" and "invoice" in i.get("selector", "")
                   for i in prop.get("items") or []),
           "the filename seed is never proposed as a domain")

        # ---- a stale approval is refused (the case moved on: a new collection landed) --------
        probe = os.path.join(O.ROOT, "cases", CASE, "raw", "stale-probe.example.json")
        os.makedirs(os.path.dirname(probe), exist_ok=True)
        with open(probe, "w") as fh:
            json.dump(_raw("epsilon.example"), fh)
        rw_id = rw[0]["id"] if rw else "missing"
        ok(P.approve(O.ROOT, CASE, only=[rw_id]).get("stale"),
           "approving after the case moved on is refused as stale")
        os.remove(probe)

        # ---- run 2: approve ONLY the purchase → estate grows, pauses for counterparties ----
        ok(P.approve(O.ROOT, CASE, only=[rw_id]).get("status") == "approved",
           "the analyst's approval is accepted after the real hand-back rewrote state.json")
        run([EMAIL])
        ok(log["gate_in_loop"] == [False],
           "an unapproved metered pivot attempted during the loop is DENIED by audit.gate")
        ok(metered_runs() == ["rwhois.purchase"], "only the approved metered pivot ran")
        prop2 = P.load(O.ROOT, CASE) or {}
        ok(log["stops"][-1] == "awaiting-approval"
           and any(i.get("tool") == "crypto.counterparties" for i in prop2.get("items") or []),
           "an unknown-size pivot (counterparties) waits for approval")
        ok(OWNERS <= cs.collected_hosts(os.path.join(O.ROOT, "cases", CASE)),
           "free work drains first: the whole owner estate was collected while counterparties waited")

        # ---- run 3: approve all → converges -------------------------------------------------
        P.approve(O.ROOT, CASE, approve_all=True)
        run([EMAIL])
        final = log.get("final")
        ok(log["stops"][-1] == "plan-veto" and cs.load_state(CASE).get("status") == "awaiting-analyst",
           f"run 3 hands back once only planner-dropped leads remain — not `cold` ({log['stops'][-1]})")
        collected = cs.collected_hosts(os.path.join(O.ROOT, "cases", CASE))
        ok(OWNERS | KIT | NEIGHBOUR <= collected,
           "every owner, kit and neighbour host was COLLECTED (seed fully)")
        ok("invoice.zip" not in collected and "invoice.zip" not in log["collect_seeds"],
           "invoice.zip was never collected (no fetch, no WHOIS)")
        attributed = {m.domain for m in (final.cluster if final else [])}
        ok(attributed == OWNERS, f"attributed cluster is exactly the owner estate ({sorted(attributed)})")
        ok(final is not None and {m.value for m in final.kit_siblings} >= KIT
           and {m.value for m in final.neighbours} >= NEIGHBOUR,
           "kit hosts land in kit_siblings and the co-tenant in neighbours, with caveats")
        comps = O._compute_components(CASE, sorted(collected))
        judged = {h for c in comps for h in c}
        ok(not (judged & (KIT | NEIGHBOUR)) and OWNERS <= judged,
           "the judged partition keeps kit/neighbour hosts out despite the shared favicon")
        tp = os.path.join(O.ROOT, "cases", CASE, "tiers.json")
        tiers = json.load(open(tp)) if os.path.exists(tp) else {}
        tiers.setdefault("kit_siblings", []), tiers.setdefault("neighbours", [])
        ok(set(tiers["kit_siblings"]) == KIT and set(tiers["neighbours"]) == NEIGHBOUR,
           "tiers.json lists the kit siblings and neighbours")
        kb = KB(kbdir)
        typed_edges = [e for e in kb.edges() if str(e.get("collector", "")).startswith("pivot_routes")]
        decoy_vals = KIT | NEIGHBOUR | {EXCH}
        ok(typed_edges and not any(any(d in str(e.get(k, "")) for d in decoy_vals)
                                   for e in typed_edges for k in ("src", "dst")),
           "cross-type ingest drew owner edges only — no edge to a kit/neighbour host or the exchange wallet")
        st = cs.load_state(CASE)
        ok(any(n.get("type") == "telegram" for n in st["nodes"].values()),
           "the Wayback telegram hit became a typed telegram node")
        ok(not any("mention" == n.get("type") for n in st["nodes"].values()),
           "a news mention is a fact, never a node")
        bad = cs.accept_extras(CASE, [
            {"type": "domain", "selector": "invoice.zip", "tool": "collect", "by": "planner"},
            {"type": "string", "selector": "kit phrase", "tool": "nope.route", "by": "planner"},
            {"type": "wallet", "selector": WALLET, "tool": "urlscan.filename", "by": "planner"}])
        ok(log["plan_adds"] >= 1 and bad == [] and not any(r == "nope.route" for r, _ in log["run"]),
           "planner additions with filename-as-domain / unknown route / type-mismatch are refused")

        # ---- no_spend scope: no preview, no metered proposal --------------------------------
        log["rw_modes"].clear()
        O._SCOPE_CACHE[CASE_NS] = case_scope.resolve(CASE_NS, root=sandbox, no_spend=True)
        before = len(metered_runs())
        run([EMAIL], case=CASE_NS)
        p_ns = P.load(O.ROOT, CASE_NS) or {}
        ok(not log["rw_modes"] and len(metered_runs()) == before
           and not any(i.get("metered") for i in p_ns.get("items") or []),
           "no_spend: no reverse-WHOIS preview, no metered run, nothing metered proposed")
        ok(not audit.decide("reverse_whois", {"term": EMAIL, "kind": "email"}, case=CASE_NS)[0],
           "no_spend: a metered reverse-WHOIS is denied by the gate even outside the loop")
        ok(not audit.decide("pivot_extract", {"url": "https://a.example", "case": CASE_NS},
                            case=CASE_NS)[0]
           and audit.decide("pivot_extract", {"url": "https://a.example", "case": CASE_NS,
                                              "free_only": True}, case=CASE_NS)[0],
           "no_spend: ANY metered tool (pivot_extract without free_only) is denied; free_only passes")
        ns_counts = [c for c in log["counts"] if c[0] == CASE_NS]
        ok(ns_counts and all(f for _c, _r, f in ns_counts),
           "no_spend: every count probe ran free_only (no keyed count, no reverse-WHOIS preview)")

        # ---- KB shape: one entity per selector, owner edges clustering can read --------------
        from selector_types import kb_key
        ok(kb_key("string", GTM) == ("indicator", f"google_tag_manager:{GTM}")
           and kb_key("wallet", WALLET) == ("indicator", f"wallet:eth:{WALLET}"),
           "a typed GTM id / wallet is the SAME KB entity the page ingest writes")
        owner_typed = [e for e in typed_edges if e.get("src_type") == "domain"]
        ok(any(e.get("src") == "delta.example" and e.get("dst") == f"wallet:eth:{WALLET}"
               for e in owner_typed),
           "an owner corpus hit is written domain→selector (the direction clustering reads)")
        ok("telegram" in {n.get("type") for n in st["nodes"].values()}
           and sum(1 for r, _q in log["run"] if r == "wayback.telegram") >= 2,
           "a transient corpus error is retried next round, not dropped as pivoted")
        cs.add_nodes(CASE, [{"type": "domain", "value": "unlabeled.example"}],
                     origin_type="string", origin_value="x", route="urlscan.title")
        ok(cs.tier_hosts(os.path.join(O.ROOT, "cases", CASE)).get("unlabeled.example") == "kit",
           "a corpus row with no rung class is kit, never owner")

        # ---- a planner that vetoes everything hands back, it does not declare `cold` --------
        log["veto"] = True
        O._SCOPE_CACHE["_XTYPE_TEST_VETO"] = case_scope.resolve("_XTYPE_TEST_VETO", root=sandbox,
                                                                persist=False)
        run([EMAIL], case="_XTYPE_TEST_VETO")
        log["veto"] = False
        ok(log["stops"][-1] == "plan-veto"
           and cs.load_state("_XTYPE_TEST_VETO").get("status") == "awaiting-analyst",
           "a full planner veto stops as awaiting-analyst (handed back), never cold")

        # ---- consent is PER HOST: the typed seed collects keyed, nothing else does ------------
        #      (live-run leak: inside round 1 an agent collected other hosts and ran deep_profile
        #       with paid layers because consent was granted to the whole round)
        SC = "_XTYPE_TEST_SEED"
        O._SCOPE_CACHE[SC] = case_scope.resolve(SC, root=sandbox, persist=False)
        log["collect_loop"] = []
        asyncio.run(O.run_case(["beta.example"], SC, hostile=False, depth=3, stale=2, max_new=8))
        phases = [a for c, a in log["collect_loop"] if c == SC]
        P.set_loop_active(O.ROOT, SC, True)
        ok(phases and all(phases)
           and not P.collect_free_only(O.ROOT, SC, "https://beta.example/")
           and P.collect_free_only(O.ROOT, SC, "scamcheck.example")
           and not P.collect_free_only(O.ROOT, SC, "scamcheck.example", allow_spend=True),
           "the loop gate is on from round 1; only the typed seed (or an approved enrich) is keyed")
        ok(audit.decide("pivot_extract", {"url": "beta.example", "case": SC}, case=SC)[0]
           and not audit.decide("pivot_extract", {"url": "scamcheck.example", "case": SC}, case=SC)[0]
           and not audit.decide("deep_profile", {"selector": "x@scamcheck.example", "case": SC},
                                case=SC)[0],
           "round 1: keyed collect of the seed passes; another host or deep_profile is denied")
        P.set_loop_active(O.ROOT, SC, False)

        # ---- gate boundaries, single-use approvals, leases, operator-only approval ----------
        mk = lambda est, m=False: {"metered": m, "est_hits": est}  # noqa: E731
        a_, n_, d_ = P.split([mk(25), mk(26), mk(None), mk(1, True)], no_spend=False, auto_max=25)
        ok(len(a_) == 1 and len(n_) == 3 and not d_, "split: N → auto; N+1, unknown, metered → proposal")
        fofa = {"id": "f0f0f0f0f0", "type": "string", "selector": "kit phrase", "tool": "fofa.body",
                "query": 'body="kit phrase"', "metered": True, "est_hits": None}
        call = {"route": "fofa.body", "query": 'body="kit phrase"', "case": CASE}
        P.set_loop_active(O.ROOT, CASE, True)
        P.write(O.ROOT, CASE, round_no=9, items=[fofa])
        P.approve(O.ROOT, CASE, only=["f0f0f0f0f0"])
        P.begin_run(O.ROOT, CASE)
        first, second = audit.decide("corpus_search", call, case=CASE)[0], \
            audit.decide("corpus_search", call, case=CASE)[0]
        ok(first and not second, "an approval lets exactly one metered call through (single-use)")
        data = P.load(O.ROOT, CASE)
        data["used"], data["run_lease_until"] = [], "2000-01-01T00:00:00Z"
        P._save(O.ROOT, CASE, data)
        ok(not audit.decide("corpus_search", call, case=CASE)[0],
           "a `running` approval whose lease expired (killed run) lets nothing through")
        data["loop_lease_until"] = "2000-01-01T00:00:00Z"
        P._save(O.ROOT, CASE, data)
        ok(audit.decide("corpus_search", call, case=CASE)[0],
           "an expired loop lease releases the gate (a killed run cannot hold it shut)")
        ok(not audit.decide("case_approve", {"case": CASE, "confirm": True}, phase="plan")[0]
           and audit.decide("case_approve", {"case": CASE}, phase="interactive")[0],
           "case_approve is denied from a harness phase, allowed interactively")

        # ---- regressions from the first live run (CASE-0001) --------------------------
        # (a) one apex reached through many sub-host forms is ONE candidate, never re-collected
        from selector_types import Candidate
        many = [Candidate.from_dict({"type": "domain", "selector": f"{p}.gamma.example",
                                     "tool": "collect", "query": f"{p}.gamma.example",
                                     "sources": ["sdk.infra"], "by": "sdk"})
                for p in ("mail", "admin", "webmail", "autodiscover")]
        many += [Candidate.from_dict({"type": "domain", "selector": f"{p}.fresh-apex.example",
                                      "tool": "collect", "query": f"{p}.fresh-apex.example",
                                      "sources": ["sdk.infra"], "by": "sdk"})
                 for p in ("mail", "admin", "www")]
        got = [c for c in cs.propose(CASE, extra=many, probe=False) if c.tool == "collect"]
        ok(not any(c.selector == "gamma.example" for c in got)
           and [c.selector for c in got].count("fresh-apex.example") == 1,
           "sub-host forms collapse to one apex candidate; an already-collected apex is not re-proposed")
        # (b) a bare case id never resolves to a stray <cwd>/<id>/ directory
        stray = os.path.join(os.getcwd(), CASE)
        made = not os.path.exists(stray)
        os.makedirs(stray, exist_ok=True)
        try:
            ok(cs._case_dir(CASE) == os.path.join(O.ROOT, "cases", CASE),
               "a bare case id resolves to cases/<id>, never a same-named dir in the CWD")
        finally:
            if made:
                shutil.rmtree(stray, ignore_errors=True)
        # (c) while the loop is active, a NON-gated metered tool is denied too
        P.set_loop_active(O.ROOT, CASE, True)
        ok(not audit.decide("deep_profile", {"selector": EMAIL, "case": CASE}, case=CASE)[0]
           and audit.decide("deep_profile", {"selector": EMAIL, "case": CASE, "free_only": True},
                            case=CASE)[0],
           "loop active: an unapproved metered call (deep_profile) is denied; free_only passes")
        P.set_loop_active(O.ROOT, CASE, False)
        # (d) an IP co-tenant reached by the frontier is collected as a neighbour, never owner
        ok(cs._frontier_rung(["ip_cohost"]) == "neighbour"
           and cs._frontier_rung(["ip_cohost", "crtsh_san"]) == "owner"
           and cs._frontier_rung(["urlscan_related"]) == "kit"
           and cs._frontier_rung(["censys_cert"]) == "owner"
           and cs._frontier_rung(["validin_subdomain"]) == "owner"
           and cs._frontier_rung(["passive_dns"]) == "neighbour",
           "frontier sources map to rungs (co-host → neighbour; engine owner links stay owner)")
        infra = Candidate.from_dict({"type": "domain", "selector": "vps-host.example",
                                     "tool": "collect", "query": "vps-host.example",
                                     "rung": "neighbour", "sources": ["sdk.infra"], "by": "sdk"})
        liar = Candidate.from_dict({"type": "domain", "selector": "hunch.example", "tool": "collect",
                                    "query": "hunch.example", "rung": "owner", "by": "planner"})
        got = {c.selector: c.rung for c in cs.accept_extras(CASE, [infra.to_dict(), liar.to_dict()])}
        ok(got.get("vps-host.example") == "neighbour" and got.get("hunch.example") == "kit",
           "reverse-IP infra stays neighbour; a planner's claimed owner rung is ignored (kit)")
        # (e) a corpus pivot that returns the SEED itself as a kit hit never tiers the seed out
        cs.add_nodes(CASE, [{"type": "domain", "value": "seedonly.example", "rung_class": "title"}],
                     origin_type="string", origin_value="Seed title", route="urlscan.title")
        before = "seedonly.example" in O._tier_hosts(CASE)
        O._record_seeds(CASE, ["https://seedonly.example/"])
        ok(before and "seedonly.example" not in O._tier_hosts(CASE)
           and "unlabeled.example" in O._tier_hosts(CASE),
           "the analyst's seed is never tiered, even when a corpus pivot returns it as a kit hit")
        # (f) no paying twice: a host whose raw already carries keyed layers gets no enrich.host,
        #     and a planner re-add of an already-run search is dropped (ids from normalised query)
        cdir = os.path.join(O.ROOT, "cases", CASE)
        rp = os.path.join(cdir, "raw", "beta.example.json")
        raw = json.load(open(rp))
        raw["meta"]["enriched_with"] = ["crtsh", "fofa", "whoisxml"]
        with open(rp, "w") as fh:
            json.dump(raw, fh)
        offered = {c.selector for c in cs.propose(CASE, probe=False) if c.tool == "enrich.host"}
        ok("beta.example" not in offered and "alpha.example" in offered,
           "enrich.host is offered only for hosts not already collected with keyed layers")
        for host, fname in (("brand-reference.example", "brand-reference.example.json"),
                            ("github.com/opsorg", "github.com_opsorg.json")):
            r_ = _raw("epsilon.example")
            r_["meta"].update({"host": host, "final_url": f"https://{host}/"})
            with open(os.path.join(cdir, "raw", fname), "w") as fh:
                json.dump(r_, fh)
        offered = {c.selector for c in cs.propose(CASE, probe=False) if c.tool == "enrich.host"}
        ok(not ({"brand-reference.example", "github.com/opsorg"} & offered)
           and not ((KIT | NEIGHBOUR) & offered),
           "enrich.host needs owner evidence: no brand reference, path entry, kit or co-tenant host")
        for fname in ("brand-reference.example.json", "github.com_opsorg.json"):
            os.remove(os.path.join(cdir, "raw", fname))
        ran = [c for c in cs.propose(CASE, probe=False) if c.tool == "urlscan.filename"]
        st_ = cs.load_state(CASE)
        done_ids = set(st_.get("pivoted") or [])
        readd = cs.accept_extras(CASE, [{"type": "filename", "selector": KITFILE,
                                         "tool": "urlscan.filename", "query": KITFILE,
                                         "by": "planner"}])
        ok(not ran and not readd and done_ids,
           "a planner re-add of an already-run pivot (raw query) dedups against `pivoted`")
        # (g) approving SOME items defers the rest (proposed again); only explicit rejects stick
        items = [{"id": i, "type": "string", "selector": i, "tool": "fofa.body", "query": i,
                  "metered": True, "est_hits": None} for i in ("d1d1d1d1d1", "d2d2d2d2d2", "d3d3d3d3d3")]
        P.write(O.ROOT, CASE, round_no=7, items=items)
        res = P.approve(O.ROOT, CASE, only=["d1d1d1d1d1"], reject=["d3d3d3d3d3"])
        ok(res.get("approved") == ["d1d1d1d1d1"] and res.get("rejected") == ["d3d3d3d3d3"]
           and res.get("deferred") == ["d2d2d2d2d2"],
           "approve --only defers unlisted items; only --reject drops one for good")
        P.mark_consumed(O.ROOT, CASE)

        # (h) a co-tenant carrying its OWN GA id: the pivot is capped at the host's tier and its
        #     hits — even the co-tenant itself, returned under an owner identifier class — land
        #     as facts, never owner edges, and never become owner evidence (live-run regression)
        COHOST, COGA = "cohost-provider.example", "G-TEST"
        r_ = _raw("epsilon.example")
        r_["meta"].update({"host": COHOST, "final_url": f"https://{COHOST}/"})
        r_["artifacts"]["trackers"] = {"google_analytics_ga4": [COGA]}
        r_["artifacts"]["whois"].pop("registrant_email", None)
        with open(os.path.join(cdir, "raw", f"{COHOST}.json"), "w") as fh:
            json.dump(r_, fh)
        T.ingest(CASE)
        cs.add_nodes(CASE, [{"type": "domain", "value": COHOST, "rung_class": "ip.cotenant"}],
                     origin_type="ip", origin_value="192.0.2.10", route="collect:ip_cohost")
        ga = [c for c in cs.propose(CASE, probe=False) if c.selector == COGA]
        ok(ga and all(c.rung in ("kit", "neighbour") for c in ga),
           f"a GA id seen only on a co-tenant is a non-owner pivot ({sorted({c.rung for c in ga})})")
        PR.run = lambda route, query, **k: {"rows": [
            {"type": "domain", "value": COHOST, "rung_class": "analytics.ga", "source": route},
            {"type": "domain", "value": "provider-customer.example", "rung_class": "analytics.ga",
             "source": route}], "total": 2}
        before = {(e.get("src"), e.get("dst")) for e in KB(kbdir).edges()}
        PR.execute("urlscan.identifier", f"content.identifiers:google.gtag-id.{COGA}", case=CASE,
                   origin_type="string", origin_value=COGA, kb_root=kbdir, rung_cap=ga[0].rung)
        new_edges = [e for e in KB(kbdir).edges() if (e.get("src"), e.get("dst")) not in before]
        ok(not new_edges and COHOST not in cs._owner_evidence_hosts(cdir, cs.load_state(CASE))
           and "provider-customer.example" not in cs._owner_evidence_hosts(cdir, cs.load_state(CASE)),
           "capped hits write no owner edge and create no owner evidence (no self-promotion)")
        PR.run = fake_run
        os.remove(os.path.join(cdir, "raw", f"{COHOST}.json"))

        # (i) a crt.sh co-SAN mined from a NEIGHBOUR host's certificate is never an owner collect
        #     (live run: capfun.com / infoclip.fr / namira.com.vn became owner evidence this way)
        fr_ = {"candidates": {"unrelated-customer.example": {
            "sources": {"crtsh_san"}, "origins": {COHOST}, "hop": 2}}}
        tier_ = {COHOST: "neighbour"}
        got_ = cs._domain_cands_from_frontier(fr_, 25, lambda h: tier_.get(h, "kit"))
        ok(got_ and got_[0].rung == "neighbour",
           "a co-SAN on a neighbour's certificate is collected as a neighbour, never owner")
        fr_["candidates"]["unrelated-customer.example"]["origins"] = {"alpha.example"}
        got_ = cs._domain_cands_from_frontier(fr_, 25, lambda h: "owner")
        ok(got_ and got_[0].rung == "owner", "the same co-SAN on an OWNER host's certificate stays owner")

        # (j) a resume run judges the analyst's seed together with the new hosts — a round can
        #     never replace the case assessment with a verdict about peripheral hosts alone
        judged = []
        real_inv = O.investigate

        async def _spy_investigate(seeds, case_, **kw):
            judged.append(list(seeds))
            return await real_inv(seeds, case_, **kw)
        O.investigate = _spy_investigate
        try:
            # a resume that brings ONE new host: the round must judge it together with the seed
            asyncio.run(O.run_case(["beta.example", "late-host.example"], SC, hostile=False,
                                   depth=1, stale=2, max_new=8, resume=True))
        finally:
            O.investigate = real_inv
        ok(judged and all("beta.example" in s for s in judged)
           and any("late-host.example" in s for s in judged),
           f"a judged round on resume includes the analyst's seed with the new host ({judged})")
        judged.clear()
        O.investigate = _spy_investigate
        try:
            # a resume that brings NOTHING new must still re-judge the seed (case assessment)
            asyncio.run(O.run_case(["beta.example"], SC, hostile=False, depth=1, stale=2,
                                   max_new=8, resume=True))
        finally:
            O.investigate = real_inv
        ok(judged == [["beta.example"]],
           f"a resume with no new host still re-judges the seed ({judged})")
    finally:
        for n, v in saved.items():
            setattr(O, n, v)
        for m, a, v in saved_roots:
            setattr(m, a, v)
        T.KB_DIR, cs.KB_DIR, PR.run, PR.count = saved_mod[:4]
        O._SCOPE_CACHE.clear()
        O._SCOPE_CACHE.update(saved_mod[4])
        shutil.rmtree(sandbox, ignore_errors=True)       # removes the symlinks, never their targets
        shutil.rmtree(kbdir, ignore_errors=True)
    return passed, failed, out


def main():
    passed, failed, lines = check()
    for status, label in lines:
        print(f"  {'ok  ' if status == 'ok' else 'FAIL'} {label}")
    print(f"\n{'PASS' if not failed else 'FAIL'} — {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
