#!/usr/bin/env python3
"""wp_quarry — client for a Quarry scan platform exposed as a Streamable-HTTP MCP server.

Quarry already scanned (or will scan) the seed and keeps the vendor answers. Reading them back
is free; starting a scan spends the SAME vendor accounts this skill uses, so the caller decides
whether a scan may start (quarry_bridge.py). This module only speaks the protocol.

  * `import wp_common` FIRST — installs the cti-proxy opener as an import side effect, so every
    urlopen here egresses through /cti-proxy. NEVER build a custom opener or use `requests`.
  * Keyless-safe: no QUARRY_API_KEY -> every call returns an error dict and nothing egresses.
  * Tri-state: a result dict on success, `{"skipped": reason}` when the server has no data,
    `{"error": reason, "kind": ...}` for transport/auth faults. Never raises.
  * NO local usage cap (project decision): the vendor's own 429 is the limit. Transient faults
    (network, 5xx, 429, a session the server forgot after a restart) are reported as
    kind="transient" so the caller can back off and retry for as long as it is willing to wait;
    kind="auth" is terminal.
  * Attribution rails live in quarry_bridge.py, not here: this client returns Quarry's own JSON
    and classifies nothing.
  * Tool-list freshness: Quarry fingerprints its tool set into serverInfo.version and treats a
    session that calls tools without listing them as stale (notifications/tools/list_changed plus
    a notice block appended to the result). Every session lists tools right after initialize,
    re-lists when the server pushes list_changed, and refuses a tool the current list lacks.

Endpoints and timings: references/quarry.json (RULE 3). Endpoint URL and key: environment.
"""
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wp_common import _secret, DEFAULT_UA  # noqa: E402 — shared .env loader + UA + proxy install

try:                                        # reference-file loader (optional; degrade to fallback)
    from wp_refs import load_ref, ref_path  # noqa: E402
except Exception:                           # noqa: BLE001
    def load_ref(path, fallback):
        return dict(fallback)

    def ref_path(module_file, name):
        return os.path.normpath(os.path.join(os.path.dirname(module_file), os.pardir,
                                             "references", name))

try:
    import api_usage                         # licensed-API call ledger (optional)
except Exception:                            # noqa: BLE001
    api_usage = None

# DATA: protocol version, timeouts, classification tables. Overridable via
# references/quarry.json (RULE 3); the fallback is the conservative minimum that keeps a
# file-less run correct — the same rails, fewer classification entries.
_QUARRY_FALLBACK = {
    "connection": {"protocol_version": "2025-06-18", "timeout_s": 150, "status_wait": True},
    "polling": {"poll_seconds": 60, "backoff_initial_s": 30, "backoff_max_s": 600,
                "heartbeat_minutes": 15, "max_resubmits": 1},
    "fetch": {"connected_page": 200, "connected_max": 2000},
    "target_class_map": {"unknown": "unknown"},
    "kind_rungs": {"ip": "ip.cotenant", "nameserver": "neighbour_link"},
    "finding_rungs": {"emails": "page.email", "phones": "page.phone"},
}
_Q = load_ref(ref_path(__file__, "quarry.json"), _QUARRY_FALLBACK)
CONNECTION = dict(_Q["connection"])
POLLING = dict(_Q["polling"])
FETCH = dict(_Q["fetch"])
TARGET_CLASS_MAP = dict(_Q["target_class_map"])
KIND_RUNGS = dict(_Q["kind_rungs"])
FINDING_RUNGS = dict(_Q["finding_rungs"])

# Quarry finding/connection kinds whose value is a tracker id, classified per value below.
TRACKER_CLASS = "tracker"

_LIST_CHANGED = "notifications/tools/list_changed"

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def quarry_key() -> str:
    return _secret("QUARRY_API_KEY", "QUARRY_KEY") or ""


def quarry_url() -> str:
    return (os.environ.get("QUARRY_MCP_URL") or "").strip()


def quarry_configured() -> bool:
    """True when an endpoint AND a key are set — the gate every caller checks before egress."""
    return bool(quarry_url()) and bool(quarry_key())


def quarry_mode() -> str:
    """'on' | 'off' | 'ask'. Unset with a key present is 'ask'; no key is always 'off'."""
    raw = (os.environ.get("QUARRY_ENABLED") or "").strip().lower()
    if raw in _FALSE:
        return "off"
    if not quarry_configured():
        return "off"
    if raw in _TRUE:
        return "on"
    return "ask"


def _record(action, results, ok=True):
    """Ledger a call that SPENDS (a scan submission). Polls and reads are not metered."""
    if api_usage:
        try:
            api_usage.record("quarry", action, credits=0, query=action, results=results, ok=ok)
        except Exception:                    # noqa: BLE001
            pass


def _fail(kind, reason, status=None):
    out = {"error": reason, "kind": kind}
    if status is not None:
        out["status"] = status
    return out


class Session:
    """One MCP session. Re-initialises itself after the server forgets it (restart)."""

    def __init__(self, url=None, key=None, opener=None):
        self.url = url or quarry_url()
        self.key = key or quarry_key()
        self.opener = opener or urllib.request.urlopen
        self.session_id = None
        self._id = 0
        self.server = {}
        self.tools = None          # name -> tool dict from the last tools/list; None = never listed
        self.list_changed = False  # the server pushed list_changed since that listing

    def _headers(self):
        h = {"User-Agent": DEFAULT_UA, "Content-Type": "application/json",
             "Accept": "application/json, text/event-stream",
             "Authorization": "Bearer " + self.key}
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        return h

    def _post(self, body):
        """One HTTP round trip -> (parsed JSON-RPC message | None, error dict | None).
        A notification (no id) expects an empty 202 and returns (None, None)."""
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(self.url, data=data, headers=self._headers())
        timeout = int(CONNECTION.get("timeout_s", 150))
        try:
            with self.opener(req, timeout=timeout) as r:
                self.session_id = r.headers.get("Mcp-Session-Id") or self.session_id
                raw = r.read().decode("utf-8", "replace")
                ctype = r.headers.get("Content-Type", "")
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                return None, _fail("auth", f"HTTP {e.code} — key rejected", e.code)
            if e.code == 404:
                return None, _fail("stale", "HTTP 404 — server forgot the session", e.code)
            if e.code == 429 or e.code >= 500:
                return None, _fail("transient", f"HTTP {e.code}", e.code)
            return None, _fail("http", f"HTTP {e.code}", e.code)
        except Exception as e:               # noqa: BLE001 — network/timeout: retryable
            return None, _fail("transient", f"{type(e).__name__}: {e}")
        if body.get("id") is None:
            return None, None
        msgs = _rpc_messages(raw, ctype)
        if any(m.get("method") == _LIST_CHANGED for m in msgs):
            self.list_changed = True
        msg = _reply(msgs, body["id"])
        if msg is None:
            return None, _fail("protocol", "response carried no JSON-RPC message")
        if msg.get("error"):
            err = msg["error"]
            text = err.get("message") if isinstance(err, dict) else str(err)
            return None, _fail("protocol", text or "JSON-RPC error")
        return msg, None

    def initialize(self):
        msg, err = self._post({
            "jsonrpc": "2.0", "id": self._next(), "method": "initialize",
            "params": {"protocolVersion": CONNECTION.get("protocol_version", "2025-06-18"),
                       "capabilities": {}, "clientInfo": {"name": "cti-expert", "version": "1"}},
        })
        if err:
            return err
        self.server = (msg.get("result") or {}).get("serverInfo") or {}
        _n, nerr = self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        if nerr:
            return nerr
        self.list_tools()          # best effort: a failed listing leaves self.tools as it was
        return None

    def list_tools(self):
        """tools/list over every page -> (name -> tool dict, error). Marks this session current
        with Quarry; on error self.tools keeps the previous listing."""
        tools, cursor, seen = {}, None, set()
        while True:
            msg, err = self._post({"jsonrpc": "2.0", "id": self._next(), "method": "tools/list",
                                   "params": {"cursor": cursor} if cursor else {}})
            if err:
                return None, err
            res = msg.get("result") or {}
            for t in res.get("tools") or []:
                if isinstance(t, dict) and t.get("name"):
                    tools[t["name"]] = t
            seen.add(cursor)
            cursor = res.get("nextCursor")
            if not cursor or cursor in seen:
                break
        self.tools, self.list_changed = tools, False
        return tools, None

    def _next(self):
        self._id += 1
        return self._id

    def call(self, name, arguments=None):
        """tools/call -> (result dict, error dict). A lost session re-initialises once. A tool
        missing from the current list comes back as a tool error without egress."""
        if not self.session_id:
            err = self.initialize()
            if err:
                return None, err
        elif self.list_changed:
            self.list_tools()
        if self.tools is not None and name not in self.tools:
            return {"error": f"Quarry no longer exposes {name} (server "
                             f"{self.server.get('version') or '?'}): its tool list changed",
                    "kind": "tool"}, None
        msg, err = self._rpc_call(name, arguments or {})
        if err and err.get("kind") == "stale":
            self.session_id = None
            err = self.initialize()
            if err:
                return None, err
            msg, err = self._rpc_call(name, arguments or {})
        if err:
            return None, err
        return _tool_result(msg), None

    def _rpc_call(self, name, arguments):
        return self._post({
            "jsonrpc": "2.0", "id": self._next(), "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        })


def _rpc_messages(raw, ctype):
    """A Streamable-HTTP reply is either one JSON body or an SSE stream of `data:` lines that may
    carry server notifications next to the answer. Returns every JSON-RPC object, in order."""
    if "event-stream" in (ctype or ""):
        out = []
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                try:
                    out.append(json.loads(line[5:].strip()))
                except ValueError:
                    continue
    else:
        try:
            out = [json.loads(raw)] if raw.strip() else []
        except ValueError:
            out = []
    return [m for m in out if isinstance(m, dict)]


def _reply(msgs, want_id):
    """The response answering request `want_id`; else the last response (no `method`)."""
    responses = [m for m in msgs if "method" not in m]
    for m in responses:
        if m.get("id") == want_id:
            return m
    return responses[-1] if responses else None


def _tool_result(msg):
    """Normalise a tools/call result. Quarry reports a duplicate/in-flight scan as a 200 tool
    result whose structured content carries {"error": CODE, ...}; that is data, not a failure,
    so it comes back as the result and the caller branches on it."""
    res = (msg or {}).get("result") or {}
    if res.get("isError"):
        text = " ".join(b.get("text", "") for b in res.get("content") or []
                        if isinstance(b, dict)).strip()
        return {"error": text or "tool error", "kind": "tool"}
    sc = res.get("structuredContent")
    if isinstance(sc, dict):
        return sc
    blocks = [b.get("text", "") for b in res.get("content") or [] if isinstance(b, dict)]
    for block in blocks:                     # a JSON payload block, ignoring appended notices
        try:
            parsed = json.loads(block) if block.strip() else None
        except ValueError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return {"text": " ".join(blocks).strip()}


def call(name, arguments=None, session=None):
    """One tool call on a fresh session. Convenience for callers that make a single call."""
    if not quarry_configured():
        return {"error": "Quarry is not configured (QUARRY_MCP_URL + QUARRY_API_KEY)",
                "kind": "config"}
    s = session or Session()
    result, err = s.call(name, arguments or {})
    return err or result


__all__ = ["quarry_configured", "quarry_mode", "quarry_url", "Session", "call",
           "CONNECTION", "POLLING", "FETCH", "TARGET_CLASS_MAP", "KIND_RUNGS",
           "FINDING_RUNGS", "TRACKER_CLASS", "_record"]
