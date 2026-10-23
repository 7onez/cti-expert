"""provider_api.py — the dashboard's model-provider surface (OrcaRouter Cyber Inference).

WHY IT LIVES BESIDE THE READ-ONLY PANELS
  The other views replay ledgers and never mutate anything. Configuring a provider is the one
  thing here that must write (a credential) and reach out (the model catalog), so it is kept in
  its own module with its own routes and its own state, rather than spreading a write path through
  `collect.py`. The server itself is still loopback-only.

WHAT THE BROWSER MAY SEE
  Never the key. A pasted key is POSTed once, written to the skill-root `.env` (chmod 600), and
  every response carries only `masked`, `source`, `generation` and `needs_reauth`. Model
  discovery happens HERE, on the server, with the stored credential; the page receives model
  metadata only. There is no route that returns a credential value.

LOGIN LIFECYCLE
  One attempt at a time, identified by a monotonically increasing `attempt` number. Every
  asynchronous completion re-checks that number before it writes a credential, so a slow reply
  from an abandoned attempt cannot overwrite a newer login. `cancel` invalidates the attempt and
  closes the loopback listener synchronously; `pagehide` calls it with keepalive from the page so
  a back-forward-cache restore does not stay stuck in "authorizing".
"""
from __future__ import annotations

import os
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))            # harness/dashboard/
HARNESS = os.path.dirname(HERE)                              # harness/
if HARNESS not in sys.path:
    sys.path.insert(0, HARNESS)

import orcarouter as orc  # noqa: E402


class ConnectManager:
    """Server-side owner of the single in-flight PKCE attempt."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.attempt = 0
        self.state = "idle"           # idle | pending | awaiting_code | connected | error
        self.error = ""
        self.url = ""
        self.flow = "loopback"
        self._flow_obj = None
        self._session = None
        self._thread = None
        self._oob_code = None
        self._oob_event = threading.Event()

    # -- public API --------------------------------------------------------
    def status(self) -> dict:
        with self._lock:
            cred = orc.credential()
            return {
                "state": self.state,
                "attempt": self.attempt,
                "flow": self.flow,
                "authorize_url": self.url,
                "error": self.error,
                "credential": None if cred is None else {
                    "masked": cred.masked,
                    "source": cred.source,
                    "generation": cred.generation,
                    "scope": cred.scope,
                    "needs_reauth": orc.needs_reauth(cred),
                },
            }

    def start(self, flow: str = "loopback") -> dict:
        if flow not in ("loopback", "oob"):
            raise ValueError("flow must be 'loopback' or 'oob'")
        with self._lock:
            self.attempt += 1
            attempt = self.attempt
            self._stop_locked()
            self.state = "pending"
            self.error = ""
            self.flow = flow
            self._oob_code = None
            self._oob_event = threading.Event()
            fo = orc.PkceFlow(flow=flow, open_browser=False)
            self._flow_obj = fo
            session = fo.start()
            self._session = session
            self.url = session.url
            if flow == "oob":
                self.state = "awaiting_code"
            t = threading.Thread(target=self._run, args=(fo, session, attempt), daemon=True)
            self._thread = t
            t.start()
        return self.status()

    def submit_code(self, code: str) -> dict:
        with self._lock:
            if self.state != "awaiting_code":
                return self.status()
            self._oob_code = (code or "").strip()
            self._oob_event.set()
        return self.status()

    def cancel(self) -> dict:
        with self._lock:
            self.attempt += 1                     # invalidate anything still in flight
            self._stop_locked()
            self.state = "idle"
            self.error = ""
            self.url = ""
        return self.status()

    def clear_credential(self) -> dict:
        with self._lock:
            orc.ApiKeyAdapter().clear()
            orc.clear_unauthorized()
        return self.status()

    # -- internals ---------------------------------------------------------
    def _stop_locked(self) -> None:
        fo, self._flow_obj = self._flow_obj, None
        self._session = None
        self._oob_event.set()
        if fo is not None:
            try:
                fo.cancel()                       # closes the loopback listener now
            except Exception:  # noqa: BLE001
                pass

    def _run(self, fo, session, attempt: int) -> None:
        try:
            if session.flow == "oob":
                if not self._oob_event.wait(timeout=600):
                    return self._finish(attempt, "error", "authorization timed out")
                if not self._current(attempt):
                    return
                code = self._oob_code or ""
                if not code:
                    return self._finish(attempt, "error", "no code supplied")
            else:
                code = fo.wait(session, timeout=600)
            if not self._current(attempt):
                return                        # a newer attempt owns the UI and the store
            with self._lock:
                if self.attempt != attempt:
                    return
                self.state = "pending"
            cred = fo.exchange(session, code)
            if not self._current(attempt):
                return                        # late success must not overwrite a newer login
            orc.ApiKeyAdapter().save(cred.api_key)
            orc.clear_unauthorized()
            self._finish(attempt, "connected", "")
        except orc.ConnectError as e:
            self._finish(attempt, "error", str(e))
        except Exception as e:  # noqa: BLE001 — never leave the UI busy on an unexpected fault
            self._finish(attempt, "error", f"{type(e).__name__}")
        finally:
            try:
                fo.cancel()
            except Exception:  # noqa: BLE001
                pass

    def _current(self, attempt: int) -> bool:
        with self._lock:
            return self.attempt == attempt

    def _finish(self, attempt: int, state: str, error: str) -> None:
        with self._lock:
            if self.attempt != attempt:
                return                        # the attempt was superseded: touch nothing
            self.state = state
            self.error = error
            if state != "connected":
                self.url = ""


_MANAGER = ConnectManager()


# ------------------------------------------------------------------ routing
def handle_get(path: str, query: dict) -> tuple[int, dict]:
    if path in ("/api/provider/state", "/api/provider/status"):
        summary = orc.provider_summary()
        return 200, {**summary, "connect": _MANAGER.status(),
                     "env_file": orc.env_path()}
    if path == "/api/provider/models":
        capability = query.get("capability", "chat")
        modality = query.get("modality") or None
        cat = orc.fetch_catalog(capability=capability, modality=modality)
        return 200, cat.to_dict()
    if path == "/api/provider/connect/status":
        return 200, _MANAGER.status()
    return 404, {"error": f"unknown provider view {path!r}"}


def handle_post(path: str, body: dict) -> tuple[int, dict]:
    if path == "/api/provider/key":
        key = str(body.get("api_key") or "").strip()
        if not key:
            return 400, {"error": "no key supplied"}
        try:
            cred = orc.ApiKeyAdapter().save(key)
        except (ValueError, OSError) as e:
            return 400, {"error": f"could not store the key: {type(e).__name__}"}
        orc.clear_unauthorized()
        warning = "" if orc.looks_like_key(key) else (
            "that does not look like an sk-orca-… key; saving anyway — the first real request "
            "decides validity")
        return 200, {"saved": True, "masked": cred.masked, "warning": warning,
                     "connect": _MANAGER.status()}
    if path == "/api/provider/key/clear":
        st = _MANAGER.clear_credential()
        return 200, {"cleared": True, "connect": st}
    if path == "/api/provider/connect":
        flow = str(body.get("flow") or "loopback")
        try:
            st = _MANAGER.start(flow)
        except (ValueError, OSError) as e:
            return 400, {"error": f"could not start authorization: {type(e).__name__}"}
        return 200, st
    if path == "/api/provider/connect/code":
        return 200, _MANAGER.submit_code(str(body.get("code") or ""))
    if path == "/api/provider/connect/cancel":
        return 200, _MANAGER.cancel()
    return 404, {"error": f"unknown provider action {path!r}"}


def start_stamp() -> float:
    return time.time()
