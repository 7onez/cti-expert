#!/usr/bin/env python3
"""Quarry bridge rails: classification, the enable decision, the wait's fault handling, and the
import. A wrong rung here is the expensive kind — an owner edge names a third party, a dropped
owner link loses the case — so each test defends one rail."""
import json
import os
import sys
import tempfile
import urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(ROOT, "intel_engine")
sys.path.insert(0, os.path.join(ENGINE, "tools"))
sys.path.insert(0, os.path.join(ENGINE, "WebPivot", "tools"))
sys.path.insert(0, os.path.join(ENGINE, "tools", "kb"))

import quarry_bridge as qb                     # noqa: E402
import wp_quarry as q                          # noqa: E402

_passed = _failed = 0
_lines = []


def ok(cond, label):
    global _passed, _failed
    if cond:
        _passed += 1
        _lines.append(("PASS", label))
    else:
        _failed += 1
        _lines.append(("FAIL", label))


def _bundle(findings=None, whois_history=None, connections=None):
    return {
        "export": {"content": {
            "findings": findings or {},
            "whois": {"whois_history": whois_history or []},
        }},
        "connected": {"connections": connections or []},
    }


def _rungs(groups):
    return {(r["type"], r["value"]): r["rung_class"] for g in groups for r in g["rows"]}


def _seeded(groups):
    return sorted(r["value"] for g in groups if g["seed"] for r in g["rows"] if r["type"] == "domain")


def test_classification():
    groups, notes = qb.build_row_groups(_bundle(
        findings={"emails": [{"value": "registrant@example.com", "subtype": "page"}],
                  "tracking_ids": [{"value": "G-TEST"}],
                  "crypto": [{"value": "0x" + "ab" * 20, "subtype": "ethereum"}],
                  "ip_address": [{"value": "203.0.113.5"}, {"value": "104.16.0.1"}]},
        whois_history=[{"registrant": {"email": "owner@example.com", "phone": "+15550100001"}},
                       {"registrant": {"email": "abuse@support.gandi.net"}}],
        connections=[{"domain": "site-b.example",
                      "shared": [{"kind": "cert_sha256", "value": "a" * 64}]}]),
        target="site-a.example")
    rungs = _rungs(groups)
    ok(rungs.get(("email", "owner@example.com")) == "whois.registrant_email",
       "a real registrant email is an owner link")
    ok(("email", "abuse@support.gandi.net") not in rungs,
       "a registrar abuse address is dropped, not linked")
    ok(rungs.get(("email", "registrant@example.com")) == "page.email",
       "an email printed on the page is kit, not ownership")
    ok(rungs.get(("string", "G-TEST")) == "analytics.gtag",
       "a GA4 id on the page is an owner-class tracker")
    ok(rungs.get(("wallet", "0x" + "ab" * 20)) == "wallet.operator",
       "a non-exchange wallet on the page is an owner link")
    ok(("ip", "104.16.0.1") not in rungs, "a CDN edge IP is dropped")
    ok("site-b.example" in _seeded(groups), "a domain sharing a cert is seeded for the loop")
    ok(notes["dropped_noise"] >= 1, "dropped rows are counted, not silently lost")


def test_victim_host_downgrades():
    groups, _notes = qb.build_row_groups(_bundle(
        whois_history=[{"registrant": {"email": "owner@example.com"}}],
        connections=[{"domain": "site-b.example",
                      "shared": [{"kind": "cert_sha256", "value": "b" * 64}]}]),
        target="site-a.example", rung_cap="kit")
    rungs = _rungs(groups)
    ok(rungs.get(("email", "owner@example.com")) == "kit_link",
       "on a victim host the registrant's email is the victim's — not an owner link")
    ok("site-b.example" not in _seeded(groups),
       "on a victim host a shared cert does not seed a peer as the operator's")


def test_cotenancy_cap():
    peers = [f"peer-{n}.example" for n in range(6)]
    groups, notes = qb.build_row_groups(_bundle(connections=[
        {"domain": p, "shared": [{"kind": "cert_sha256", "value": "c" * 64}]} for p in peers]),
        target="site-a.example")
    ok(notes["co_tenancy"], "a cert naming more apexes than the cap is recorded as co-tenancy")
    ok("peer-0.example" not in _seeded(groups), "an over-cap cert never seeds its names")
    ok(all(v == "kit_link" for (t, _v), v in _rungs(groups).items() if t == "domain"),
       "over-cap cert peers are kept as kit facts, not dropped")


def test_decision(case):
    saved = {k: os.environ.get(k) for k in ("QUARRY_ENABLED", "QUARRY_API_KEY", "QUARRY_MCP_URL")}
    try:
        os.environ["QUARRY_API_KEY"] = "test-key"
        os.environ["QUARRY_MCP_URL"] = "https://quarry.example/api/mcp"
        os.environ["QUARRY_ENABLED"] = "off"
        ok(qb.resolve_decision(case, tty=False) == "off", "QUARRY_ENABLED=off never consults Quarry")
        ok(qb.resolve_decision(case, explicit=True, tty=False) == "on",
           "--quarry overrides an off default for one case")
        os.environ["QUARRY_ENABLED"] = "ask"
        os.remove(qb._decision_path(case))
        ok(qb.resolve_decision(case, tty=False) == "undecided",
           "ask with nobody to ask skips rather than scanning")
        ok(qb.resolve_decision(case, no_quarry=True, tty=False) == "off",
           "--no-quarry is remembered, so a resumed run does not re-ask")
        ok(qb.recorded_decision(case) is False, "the decision is persisted on the case")
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


class _Resp:
    def __init__(self, payload, *, session="s1", sse=False):
        self._payload = payload if isinstance(payload, bytes) else payload.encode()
        self.headers = {"Mcp-Session-Id": session,
                        "Content-Type": "text/event-stream" if sse else "application/json"}

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Opener:
    """Scripted responses. A queued HTTPError is raised like urllib raises it."""

    def __init__(self, script):
        self.script = list(script)
        self.seen = []

    def __call__(self, req, timeout):
        body = json.loads(req.data.decode())
        self.seen.append(body.get("method"))
        item = self.script.pop(0)
        if isinstance(item, urllib.error.HTTPError):
            raise item
        return item


def _http_error(code):
    return urllib.error.HTTPError("https://quarry.example/api/mcp", code, "x", {}, None)


_LISTED = b'{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"quarry_get_domain"}]}}'


def test_client_session_recovers():
    answer = ('data: {"jsonrpc":"2.0","id":4,"result":{"structuredContent":'
              '{"domain":"site-a.example"}}}\n')
    op = _Opener([
        _Resp(b'{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"quarry"}}}'),
        _Resp(b""),
        _Resp(_LISTED),
        _http_error(404),
        _Resp(b'{"jsonrpc":"2.0","id":3,"result":{"serverInfo":{"name":"quarry"}}}'),
        _Resp(b""),
        _Resp(_LISTED),
        _Resp(answer, sse=True),
    ])
    s = q.Session(url="https://quarry.example/api/mcp", key="k", opener=op)
    result, err = s.call("quarry_get_domain", {"domain": "site-a.example"})
    ok(err is None and result.get("domain") == "site-a.example",
       "a session the server forgot is re-opened and the call retried")
    ok(op.seen.count("initialize") == 2, "the stale session is re-initialised exactly once")


def test_client_tool_list_freshness():
    pushed = ('data: {"jsonrpc":"2.0","method":"notifications/tools/list_changed"}\n'
              'data: {"jsonrpc":"2.0","id":3,"result":{"content":['
              '{"type":"text","text":"{\\"domain\\": \\"site-a.example\\"}"},'
              '{"type":"text","text":"[Quarry notice] tool list changed"}]}}\n')
    relisted = b'{"jsonrpc":"2.0","id":4,"result":{"tools":[{"name":"quarry_scan"}]}}'
    op = _Opener([
        _Resp(b'{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"quarry",'
              b'"version":"1.0.0+tools.aaaa"}}}'),
        _Resp(b""),
        _Resp(_LISTED),
        _Resp(pushed, sse=True),
        _Resp(relisted),
    ])
    s = q.Session(url="https://quarry.example/api/mcp", key="k", opener=op)
    result, err = s.call("quarry_get_domain", {"domain": "site-a.example"})
    ok(op.seen[:3] == ["initialize", "notifications/initialized", "tools/list"],
       "a new session lists Quarry's tools before its first call")
    ok(err is None and result.get("domain") == "site-a.example",
       "a reply carrying list_changed and an appended notice still yields the JSON payload")
    ok(s.list_changed, "a pushed tools/list_changed marks the session's list stale")
    gone, gerr = s.call("quarry_get_domain", {"domain": "site-a.example"})
    ok(op.seen[-1] == "tools/list" and not s.list_changed,
       "the next call re-lists tools once after list_changed")
    ok(gerr is None and gone.get("kind") == "tool" and "no longer exposes" in gone.get("error", ""),
       "a tool the current list lacks is a tool error, not sent to the server")
    ok(op.seen.count("tools/call") == 1, "the removed tool never egresses")


def test_client_auth_is_terminal():
    op = _Opener([_http_error(401)])
    s = q.Session(url="https://quarry.example/api/mcp", key="k", opener=op)
    _res, err = s.call("quarry_scan", {"domain": "site-a.example"})
    ok(err and err.get("kind") == "auth", "a rejected key is auth, not retried as transient")


def test_import_and_frontier(case):
    sys.path.insert(0, os.path.join(ENGINE, "tools", "kb"))
    import ingest_typed
    from knowledge_base import KB
    kb = KB(os.path.join(case, "kb"))
    qb._kb = lambda: (ingest_typed, kb)
    groups, _notes = qb.build_row_groups(_bundle(
        whois_history=[{"registrant": {"email": "owner@example.com"}}],
        connections=[{"domain": "site-b.example",
                      "shared": [{"kind": "registrant_email", "value": "owner@example.com"}]}]),
        target="site-a.example")
    imported = qb.import_groups(case, groups, target="site-a.example")
    edges = kb.edges()
    ok(any(e["dst"] == "owner@example.com" and e["src"] == "site-a.example" for e in edges),
       "the registrant email is edged from the target domain")
    ok("site-b.example" in imported["owner_domains"], "the peer is reported as owner-linked")
    ok("site-a.example" not in imported["owner_domains"], "the seed is not reported as a discovery")
    ok(qb.seed_frontier(case, imported["owner_domains"]) == 1, "the peer is queued on the frontier")
    ok(qb.seed_frontier(case, imported["owner_domains"]) == 0, "queueing twice adds nothing")
    st = json.load(open(os.path.join(case, "state.json"), encoding="utf-8"))
    ok("site-a.example" not in st.get("pending", []), "the seed is not re-queued")
    ok(not st.get("hops"), "queueing discoveries does not anchor the case")


def test_no_spend_refuses(case):
    with open(os.path.join(case, "scope.json"), "w", encoding="utf-8") as fh:
        json.dump({"constraints": {"no_spend": True}}, fh)
    ok(qb._start_blocked(qb._scope(case), True, False, False).startswith("no-spend"),
       "a no-spend case cannot start a Quarry scan")
    ok(qb._start_blocked({"no_direct_contact": True}, True, False, False).startswith("no-contact"),
       "a no-contact case cannot start a Quarry scan")
    ok(qb._start_blocked({}, False, False, False).startswith("no existing scan"),
       "without start= a missing scan is skipped, not started")
class _ScriptSession:
    """Records tool names. Never opens a network connection."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.seen = []

    def call(self, name, arguments=None):
        self.seen.append(name)
        item = self.replies.pop(0)
        if isinstance(item, tuple):
            return item
        return item, None


def test_failed_job_is_not_resubmitted(case):
    qb._save_job(case, {"domain": "site-a.example", "job_id": "job-9", "status": "failed",
                        "error": "scan died"})
    session = _ScriptSession([
        ({"domain": "site-a.example"}, None),          # would be get_domain
        ({"job": {"id": "job-new"}}, None),            # would be a new quarry_scan
    ])
    real = q.Session
    q.Session = lambda *a, **k: session
    saved = {k: os.environ.get(k) for k in ("QUARRY_API_KEY", "QUARRY_MCP_URL")}
    os.environ["QUARRY_API_KEY"] = "test-key"
    os.environ["QUARRY_MCP_URL"] = "https://quarry.example/api/mcp"
    try:
        out = qb.sync(case, "site-a.example", start=True, wait=True, log=lambda *_a, **_k: None)
    finally:
        q.Session = real
        for k, v in saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
    ok(session.seen == [],
       f"a failed Quarry job makes no further vendor call (saw {session.seen})")
    ok(out.get("status") == "failed", "the rerun reports the failed job instead of starting one")


def test_unreadable_existing_scan_holds(case):
    import intel
    case = os.path.join(case, "dup")
    os.makedirs(case, exist_ok=True)
    session = _ScriptSession([
        ({"kind": "tool", "error": "Domain not found"}, None),
        ({"error": "SELF_DUPLICATE_SCAN", "existing": {"scanned_at": "2026-01-01"}}, None),
    ])
    real = q.Session
    q.Session = lambda *a, **k: session
    saved = {k: os.environ.get(k) for k in ("QUARRY_API_KEY", "QUARRY_MCP_URL")}
    os.environ["QUARRY_API_KEY"] = "test-key"
    os.environ["QUARRY_MCP_URL"] = "https://quarry.example/api/mcp"
    try:
        out = qb.sync(case, "site-a.example", start=True, wait=True, log=lambda *_a, **_k: None)
    finally:
        q.Session = real
        for k, v in saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
    ok(session.seen.count("quarry_scan") == 1, "an existing scan is not submitted twice")
    ok(intel._quarry_holds(out),
       f"an unreadable existing scan holds collection (got {out.get('status')})")



def check():
    test_classification()
    test_victim_host_downgrades()
    test_cotenancy_cap()
    test_client_session_recovers()
    test_client_auth_is_terminal()
    test_client_tool_list_freshness()
    with tempfile.TemporaryDirectory() as tmp:
        case = os.path.join(tmp, "CASE-0001")
        os.makedirs(case)
        test_decision(case)
        test_import_and_frontier(case)
        test_no_spend_refuses(case)
        test_failed_job_is_not_resubmitted(case)
        test_unreadable_existing_scan_holds(case)
    return _passed, _failed, _lines


if __name__ == "__main__":
    passed, failed, lines = check()
    for status, label in lines:
        print(f"{status:>4}  {label}")
    print(f"\n{passed} passed, {failed} failed")
    raise SystemExit(bool(failed))
