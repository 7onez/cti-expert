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
        msg = _parse_rpc(raw, ctype)
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
        return nerr

    def _next(self):
        self._id += 1
        return self._id

    def call(self, name, arguments=None):
        """tools/call -> (result dict, error dict). A lost session re-initialises once."""
        if not self.session_id:
            err = self.initialize()
            if err:
                return None, err
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


def _parse_rpc(raw, ctype):
    """A Streamable-HTTP reply is either one JSON body or an SSE stream of `data:` lines.
    The message answering the request is the last JSON-RPC object in the stream."""
    found = None
    if "event-stream" in (ctype or ""):
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                try:
                    found = json.loads(line[5:].strip())
                except ValueError:
                    continue
        return found
    try:
        return json.loads(raw) if raw.strip() else None
    except ValueError:
        return None


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
    text = " ".join(b.get("text", "") for b in res.get("content") or []
                    if isinstance(b, dict)).strip()
    parsed = None
    try:
        parsed = json.loads(text) if text else None
    except ValueError:
        parsed = None
    return parsed if isinstance(parsed, dict) else {"text": text}


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
