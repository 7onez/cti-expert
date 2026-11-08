"""orcarouter.py — the OrcaRouter Cyber Inference provider: credentials, catalog, model choice.

WHY THIS MODULE EXISTS
  `backend_select.py` answers "which backend runs the harness". For the OrcaRouter backend that
  answer is not complete without three things this project cannot get from a generic
  OpenAI-compatible shim: WHERE the credential came from (a pasted key or an OAuth 2.0 + PKCE
  login), WHAT the account can actually call right now (live `GET /v1/models`), and WHAT to do
  when the relay says 401 (mark the exact credential generation for reauthentication — there is
  no refresh grant to call). All three live here so `openai_backend.py` stays a transport.

TWO AUTHENTICATION CHOICES, ONE CREDENTIAL TYPE
  `ApiKeyAdapter` and `PkceAdapter` both return a `Credential`. Downstream — the provider client,
  model discovery, the dashboard — sees only `Credential` and cannot tell which path produced it.
  That is deliberate: an added auth method must never fork the inference path.

  API key     env `ORCAROUTER_API_KEY`, else the skill-root `.env` (the store `/apikeys` already
              manages, chmod 600, gitignored). Nothing new is introduced.
  PKCE        OAuth 2.0 + PKCE (S256), Flow A loopback redirect for a workstation, Flow B
              out-of-band for a headless VPS. The exchange returns a DURABLE `sk-orca-…` key,
              which is stored in the same `.env`. It is not a refresh token: there is no refresh
              grant, so a revoked key is reauthenticated, never refreshed.

ORIGINS (never derived from one another)
  authentication  https://www.orcarouter.ai        → POST /api/v1/auth/keys
  inference       https://api.orcarouter.ai/v1     → GET /models, POST /chat/completions
  Overrides, highest precedence first: ORCA_AUTH_BASE_URL / ORCA_API_BASE_URL, then the shared
  self-hosted ORCA_BASE_URL. HTTPS is required for a remote origin; plain HTTP is accepted only
  for loopback, where a local test server legitimately lives.

REFERENCE DATA
  Everything vendor-specific (origins, paths, env names, tier map, catalog bounds, outage seed)
  is in references/model_providers.json — RULE 3, data not literals. The embedded `_FALLBACK`
  below is the conservative minimum so a missing ref file degrades instead of crashing.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.server
import importlib.util
import json
import os
import secrets
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from dataclasses import dataclass, field
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))            # harness/
ENGINE = os.path.dirname(HERE)                               # intel_engine/
SKILL_ROOT = os.path.dirname(ENGINE)                         # repo / skill root

PROVIDER_ID = "orcarouter"
LABEL = "OrcaRouter Cyber Inference"

_FALLBACK = {
    "label": LABEL,
    "api_base_url": "https://api.orcarouter.ai/v1",
    "auth_base_url": "https://www.orcarouter.ai",
    "authorize_path": "/auth",
    "exchange_path": "/api/v1/auth/keys",
    "env_key": "ORCAROUTER_API_KEY",
    "env_api_base": "ORCA_API_BASE_URL",
    "env_auth_base": "ORCA_AUTH_BASE_URL",
    "env_shared_base": "ORCA_BASE_URL",
    "key_prefix": "sk-orca-",
    "app_name": "cti-expert",
    "console_url": "https://www.orcarouter.ai/console",
    "provider_page": "https://www.orcarouter.ai/cyber",
    "cyber_catalog_url": "https://www.orcarouter.ai/models?tier=cyber",
    "default_model": "orcarouter/auto",
    "fallback_model": "orcarouter/fusion",
    "cyber_models": ["orcacyber-ultra-1.0", "orcacyber-zero-1.5"],
    "tier_model_map": {"haiku": "orcarouter/auto", "sonnet": "orcarouter/auto",
                       "opus": "orcarouter/auto"},
    "catalog": {"timeout_s": 8, "max_bytes": 2097152, "max_items": 2000,
                "chat_endpoint_types": ["openai", "anthropic", "gemini", "openai-response"],
                "non_chat_endpoint_types": ["image-generation", "openai-video", "jina-rerank",
                                            "embeddings"]},
    "verified_seed": {"models": []},
}


def _load_provider() -> dict:
    try:
        import wp_refs  # the shared RULE 3 loader (WebPivot/tools)
    except Exception:  # noqa: BLE001 — degrade, never block
        wp = os.path.join(ENGINE, "WebPivot", "tools")
        if wp not in sys.path:
            sys.path.append(wp)
        try:
            import wp_refs  # noqa: F811
        except Exception:  # noqa: BLE001
            return dict(_FALLBACK)
    raw = wp_refs.load_ref(os.path.join(HERE, "references", "model_providers.json"),
                           {"providers": {PROVIDER_ID: _FALLBACK}})
    entry = (raw.get("providers") or {}).get(PROVIDER_ID) or {}
    merged = dict(_FALLBACK)
    merged.update({k: v for k, v in entry.items() if not k.startswith("_")})
    # Re-read through wp_refs, which is a deep copy — never hand out the module cache itself.
    return merged


PROVIDER = _load_provider()

_AUTH_ENV_KEY = PROVIDER["env_key"]
DEFAULT_API_BASE = PROVIDER["api_base_url"].rstrip("/")
DEFAULT_AUTH_BASE = PROVIDER["auth_base_url"].rstrip("/")


# --------------------------------------------------------------------- origins
def _is_loopback(host: str) -> bool:
    return host in ("localhost", "127.0.0.1", "::1", "[::1]")


def _checked_origin(url: str, what: str) -> str:
    """HTTPS for a remote origin; plain HTTP only for loopback. A provider origin is where a
    key is sent, so a typo'd scheme (`http://api.orcarouter.ai`) must fail loudly here."""
    u = urllib.parse.urlsplit(url)
    if u.scheme == "https" and u.hostname:
        return url.rstrip("/")
    if u.scheme == "http" and u.hostname and _is_loopback(u.hostname):
        return url.rstrip("/")
    raise ValueError(f"{what} must be https, or http on loopback (got {url!r})")


def api_base_url() -> str:
    """Inference origin. An explicit ORCA_API_BASE_URL wins; the shared self-hosted
    ORCA_BASE_URL is a fallback that gets the documented `/v1` suffix, never a hostname swap."""
    explicit = os.environ.get(PROVIDER["env_api_base"])
    if explicit:
        return _checked_origin(explicit, "ORCA_API_BASE_URL")
    shared = os.environ.get(PROVIDER["env_shared_base"])
    if shared:
        return _checked_origin(shared, "ORCA_BASE_URL") + "/v1"
    return DEFAULT_API_BASE


def auth_base_url() -> str:
    explicit = os.environ.get(PROVIDER["env_auth_base"])
    if explicit:
        return _checked_origin(explicit, "ORCA_AUTH_BASE_URL")
    shared = os.environ.get(PROVIDER["env_shared_base"])
    if shared:
        return _checked_origin(shared, "ORCA_BASE_URL")
    return DEFAULT_AUTH_BASE


def authorize_url() -> str:
    return auth_base_url() + PROVIDER["authorize_path"]


def exchange_url() -> str:
    # Authentication lives on the www origin at /api/v1/auth/keys. The inference relay's
    # /v1/auth/keys is a 404 — the single most common way this integration is built wrong.
    return auth_base_url() + PROVIDER["exchange_path"]


# ------------------------------------------------------------------- secret store
def env_path() -> str:
    """The project's own secret file — same resolution every other key in this repo uses
    (`scripts/backend/backend.py`, `/apikeys`): $CTI_API_KEYS_ENV, else <skill-root>/.env."""
    return os.environ.get("CTI_API_KEYS_ENV") or os.path.join(SKILL_ROOT, ".env")


def _read_env_file(path: str) -> dict:
    """Read KEY=VALUE lines from the skill-root `.env` (comments/blanks ignored).

    NOTE — why this does not import `scripts/apikeys/apikeys.py` to reuse its reader: that module
    installs the research egress proxy for the WHOLE process at import time
    (`_install_cti_proxy()` → `cti_proxy.install()`), which rewrites NO_PROXY and routes stdlib
    HTTP through the collector pool. A credential exchange and a loopback callback must go
    direct; routing them through a research exit is both wrong and broken. The FILE and its
    format/chmod are the shared store; only the reader/writer is local.
    """
    out = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        return {}
    return out


def mask_key(key: str) -> str:
    """What may be shown about a stored key: the provider's public prefix and its length.

    Deliberately NOT a character suffix. Operators paste CLI output and dashboard screenshots
    into case notes and tickets, so any suffix is a small, permanent leak that survives a
    rotation; the `sk-orca-` prefix identifies the provider and carries no secret entropy."""
    if not key:
        return ""
    prefix = (PROVIDER.get("key_prefix") or "").strip()
    head = prefix if prefix and key.startswith(prefix) else ""
    return f"{head}… ({len(key)} chars)"


def key_fingerprint(key: str) -> str:
    """A stable, non-reversible id for one credential GENERATION. A 401 marks exactly this —
    so a late failure from an old request cannot invalidate a key the user just re-authorised."""
    return hashlib.sha256((key or "").encode("utf-8")).hexdigest()[:16]


def looks_like_key(key: str) -> bool:
    """Format sanity only. A prefix proves nothing about validity; the first real request does."""
    prefix = PROVIDER.get("key_prefix") or "sk-orca-"
    return bool(key) and key.strip().startswith(prefix) and len(key.strip()) >= 20


@dataclass(frozen=True)
class Credential:
    """One credential, whatever produced it. `source` is for display and audit, never for
    branching in the request path."""
    api_key: str
    source: str                      # "api_key" | "env" | "pkce"
    generation: str = ""
    scope: str = "api"

    def __post_init__(self):
        if not self.generation:
            object.__setattr__(self, "generation", key_fingerprint(self.api_key))

    @property
    def masked(self) -> str:
        return mask_key(self.api_key)


class ApiKeyAdapter:
    """Paste-a-key path. Reads env first, then the .env, exactly like every other key here."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or env_path()

    def read(self) -> Optional[Credential]:
        key = (os.environ.get(_AUTH_ENV_KEY) or "").strip()
        if key:
            return Credential(api_key=key, source="env", scope="api")
        key = (_read_env_file(self.path).get(_AUTH_ENV_KEY) or "").strip()
        if key:
            return Credential(api_key=key, source="api_key", scope="api")
        return None

    def save(self, key: str) -> Credential:
        key = (key or "").strip()
        if not key:
            raise ValueError("empty API key")
        _write_env_minimal(self.path, _AUTH_ENV_KEY, key)
        return Credential(api_key=key, source="api_key", scope="api")

    def clear(self) -> None:
        _remove_env_minimal(self.path, _AUTH_ENV_KEY)
        os.environ.pop(_AUTH_ENV_KEY, None)


def _write_env_minimal(path: str, var: str, value: str) -> None:
    """Fallback writer for the (unusual) checkout where scripts/apikeys is absent. Same file,
    same 0600 mode, same in-place-update shape as the real manager."""
    lines, seen = [], False
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        lines = []
    for i, line in enumerate(lines):
        if line.split("=", 1)[0].strip() == var:
            lines[i] = f"{var}={value}"
            seen = True
    if not seen:
        lines.append(f"{var}={value}")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _remove_env_minimal(path: str, var: str) -> None:
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return
    kept = [ln for ln in lines if ln.split("=", 1)[0].strip() != var]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(kept) + ("\n" if kept else ""))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def credential() -> Optional[Credential]:
    """The credential the provider uses right now, or None. Source-agnostic by construction."""
    return ApiKeyAdapter().read()


def api_key() -> str:
    cred = credential()
    return cred.api_key if cred else ""


# ------------------------------------------------------- terminal-401 bookkeeping
def _state_path() -> str:
    override = os.environ.get("ORCA_REAUTH_STATE")
    if override:
        return override
    return os.path.join(ENGINE, "MEMORY", "orcarouter_reauth.json")


def mark_unauthorized(generation: str) -> bool:
    """Record that EXACT generation was rejected. Returns True when the marker was written.

    A 401 is terminal: the key was revoked or replaced. There is no refresh endpoint to try, and
    re-authorising on every launch would burn the 10-keys-per-24h allowance. So the only correct
    response is to point the user at a re-login — and to refuse to touch a newer credential,
    which is why the write is conditional on the generation still being the current one.
    """
    cur = credential()
    if cur is None or not generation or cur.generation != generation:
        return False
    path = _state_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"generation": generation, "needs_reauth": True, "ts": time.time()}, f)
        return True
    except OSError:
        return False


def clear_unauthorized() -> None:
    try:
        os.remove(_state_path())
    except OSError:
        pass


def needs_reauth(cred: Optional[Credential] = None) -> bool:
    cred = cred if cred is not None else credential()
    if cred is None:
        return False
    try:
        with open(_state_path(), encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, ValueError):
        return False
    return bool(state.get("needs_reauth")) and state.get("generation") == cred.generation


# ------------------------------------------------------------------------- PKCE
class ConnectError(RuntimeError):
    """An authorization failure the user can act on. The message never carries the verifier,
    the authorization code, or the key — only what happened and what to do about it."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind          # denied | state_mismatch | timeout | exchange | network | scope


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def code_challenge(verifier: str) -> str:
    """S256: base64url(sha256(verifier)), no padding. `plain` is never offered — a human can
    choose 'Show me a code' on the consent screen in Flow A too, so the challenge must not be
    the verifier."""
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


@dataclass
class PkceSession:
    """One authorization attempt. Fresh verifier and state per attempt, from a CSPRNG."""
    attempt: int
    verifier: str
    state: str
    redirect_uri: str
    url: str
    flow: str = "loopback"
    created: float = field(default_factory=time.time)
    code: Optional[str] = None
    error: Optional[str] = None
    done: threading.Event = field(default_factory=threading.Event)
    _server: Optional[http.server.HTTPServer] = None
    _thread: Optional[threading.Thread] = None

    def __repr__(self) -> str:          # a traceback must not print the verifier
        return f"PkceSession(attempt={self.attempt}, flow={self.flow}, done={self.done.is_set()})"

    def close(self) -> None:
        srv, self._server = self._server, None
        if srv is not None:
            try:
                srv.server_close()
            except OSError:
                pass


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    session: Optional[PkceSession] = None

    def log_message(self, *a):          # the callback URL carries the code: never log it
        return

    def do_GET(self):                   # noqa: N802 — BaseHTTPRequestHandler's name
        s = self.session
        parsed = urllib.parse.urlsplit(self.path)
        if s is None or parsed.path != "/cb":
            self._respond(404, "<p>Not found.</p>")
            return
        query = urllib.parse.parse_qs(parsed.query)
        state = (query.get("state") or [""])[0]
        # Compare state BEFORE looking at the code: the state is the only thing separating this
        # listener from a code some other page dropped on it.
        if not hmac.compare_digest(state, s.state):
            s.error = "state_mismatch"
            self._respond(400, "<p>Authorization failed: state mismatch. You can close this tab.</p>")
            s.done.set()
            return
        err = (query.get("error") or [""])[0]
        if err:
            s.error = err or "access_denied"
            self._respond(200, "<p>Authorization was denied. You can close this tab.</p>")
            s.done.set()
            return
        code = (query.get("code") or [""])[0]
        if not code:
            s.error = "missing_code"
            self._respond(400, "<p>Authorization failed: no code returned.</p>")
            s.done.set()
            return
        s.code = code
        self._respond(200, "<p>Connected. You can close this tab and return to the terminal.</p>")
        s.done.set()

    def _respond(self, status: int, html: str) -> None:
        body = ("<!doctype html><meta charset='utf-8'><title>OrcaRouter</title>" + html).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


class PkceFlow:
    """OAuth 2.0 + PKCE against the AUTH origin only. No client secret, no pre-registered
    redirect URI (the loopback port is chosen by the OS at start), no refresh grant."""

    def __init__(self, *, flow: str = "loopback", open_browser: bool = True,
                 app_name: Optional[str] = None, timeout: float = 600.0) -> None:
        if flow not in ("loopback", "oob"):
            raise ValueError("flow must be 'loopback' or 'oob'")
        self.flow = flow
        self.open_browser = open_browser
        self.app_name = app_name or PROVIDER.get("app_name") or "cti-expert"
        self.timeout = timeout
        self._lock = threading.Lock()
        self._attempt = 0
        self._active: Optional[PkceSession] = None

    # -- lifecycle ---------------------------------------------------------
    @property
    def attempt(self) -> int:
        with self._lock:
            return self._attempt

    def active(self) -> Optional[PkceSession]:
        return self._active

    def start(self) -> PkceSession:
        """Bind the listener FIRST (so the port is known and nothing races), then build the
        authorize URL. The verifier never leaves this process until the exchange."""
        with self._lock:
            self._attempt += 1
            attempt = self._attempt
        verifier = _b64url(secrets.token_bytes(32))
        state = _b64url(secrets.token_bytes(16))
        challenge = code_challenge(verifier)

        srv = None
        if self.flow == "loopback":
            srv = http.server.HTTPServer(("127.0.0.1", 0), _CallbackHandler)
            port = srv.server_address[1]
            redirect = f"http://127.0.0.1:{port}/cb"
        else:
            redirect = "oob"

        params = {
            "callback_url": redirect,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "app_name": self.app_name,
            "scope": "api",
        }
        url = authorize_url() + "?" + urllib.parse.urlencode(params)
        session = PkceSession(attempt=attempt, verifier=verifier, state=state,
                              redirect_uri=redirect, url=url, flow=self.flow)
        if srv is not None:
            session._server = srv
            _CallbackHandler.session = session          # the one listener the handler answers for
            t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.2},
                                 daemon=True)
            t.start()
            session._thread = t
        self._active = session
        if self.open_browser:
            try:
                webbrowser.open(url)
            except Exception:  # noqa: BLE001 — headless box: the URL is printed instead
                pass
        return session

    def wait(self, session: PkceSession, timeout: Optional[float] = None) -> str:
        """Block until the callback (Flow A) or the caller supplies a code (Flow B)."""
        if self.flow == "oob":
            raise ConnectError("timeout", "out-of-band flow: supply the code with submit_code()")
        remaining = self.timeout if timeout is None else timeout
        if not session.done.wait(timeout=max(0.0, remaining)):
            session.close()
            self._active = None
            raise ConnectError("timeout",
                               "authorization timed out — run `provider login --method oauth` again")
        session.close()
        if session.error:
            self._active = None
            if session.error == "state_mismatch":
                raise ConnectError("state_mismatch",
                                   "the callback state did not match this attempt — login aborted")
            if session.error in ("access_denied", "denied"):
                raise ConnectError("denied", "authorization was denied")
            raise ConnectError("denied", f"authorization failed: {session.error}")
        if not session.code:
            self._active = None
            raise ConnectError("exchange", "no authorization code was returned")
        return session.code

    def submit_code(self, session: PkceSession, code: str) -> str:
        """Flow B: the user pastes the code the consent screen showed."""
        code = (code or "").strip()
        if not code:
            raise ConnectError("exchange", "no code supplied")
        return code

    def cancel(self) -> None:
        s = self._active
        session, self._active = s, None
        if session is not None:
            session.error = session.error or "cancelled"
            session.close()
            session.done.set()

    # -- exchange ----------------------------------------------------------
    def exchange(self, session: PkceSession, code: str) -> Credential:
        """Redeem the code at the AUTH origin and persist the returned durable key."""
        payload = json.dumps({"code": code, "code_verifier": session.verifier,
                              "code_challenge_method": "S256"}).encode("utf-8")
        req = urllib.request.Request(exchange_url(), data=payload, method="POST",
                                     headers={"Content-Type": "application/json",
                                              "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read(65536)
                status = r.status
        except urllib.error.HTTPError as e:
            body = _safe_error_body(e)
            if e.code == 400:
                raise ConnectError("exchange",
                                   "the authorization server rejected the challenge method "
                                   "(400) — this client only sends S256") from None
            if e.code == 403:
                raise ConnectError("exchange",
                                   "the authorization code is unknown, expired or already used, "
                                   "or the verifier does not match (403) — start a new login") from None
            if e.code == 429:
                raise ConnectError("exchange",
                                   "too many authorization requests (429) — a user may issue at "
                                   "most 10 PKCE keys per 24 hours; reuse the stored key") from None
            raise ConnectError("exchange", f"key exchange failed ({e.code}): {body}") from None
        except (urllib.error.URLError, OSError, ssl.SSLError) as e:
            raise ConnectError("network",
                               f"could not reach the authorization server: {type(e).__name__}") from None

        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ConnectError("exchange", "the key exchange returned a non-JSON body") from None
        key = (data.get("key") or "").strip() if isinstance(data, dict) else ""
        if not key:
            raise ConnectError("exchange", "the key exchange returned no key")
        granted = str(data.get("scope") or "")
        # Read the scope back: it is what was GRANTED, not what was requested. A connector
        # grant cannot drive inference, so accepting it would be a silent broken credential.
        if granted and granted != "api":
            raise ConnectError("scope",
                               f'the account granted scope "{granted}", which cannot run inference '
                               '— approve the "api" scope instead')
        return Credential(api_key=key, source="pkce",
                          scope=granted or "api",
                          generation=key_fingerprint(key))


def _safe_error_body(e: urllib.error.HTTPError) -> str:
    """Server text is diagnostic only: bounded, and stripped of anything key-shaped."""
    try:
        body = e.read(2048).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""
    for token in body.split():
        if looks_like_key(token.strip('",')):
            body = body.replace(token, "[redacted]")
    return body[:300]


class PkceAdapter:
    """The credential seam's second adapter. Same output type as `ApiKeyAdapter` — a
    `Credential` persisted in the same `.env` — so nothing downstream can tell them apart, and
    a bug in one cannot be worked around by special-casing the other."""

    def __init__(self, *, flow: str = "loopback", open_browser: bool = True,
                 store: Optional[ApiKeyAdapter] = None) -> None:
        self.flow = PkceFlow(flow=flow, open_browser=open_browser)
        self.store = store or ApiKeyAdapter()

    def start(self) -> PkceSession:
        return self.flow.start()

    def wait(self, session: PkceSession, timeout: Optional[float] = None) -> str:
        return self.flow.wait(session, timeout)

    def submit_code(self, session: PkceSession, code: str) -> str:
        return self.flow.submit_code(session, code)

    def cancel(self) -> None:
        self.flow.cancel()

    def finish(self, session: PkceSession, code: str) -> Credential:
        """Exchange and persist. The key is written only after the server-side PKCE check
        passed and the granted scope was accepted."""
        cred = self.flow.exchange(session, code)
        self.store.save(cred.api_key)
        clear_unauthorized()          # a successful login supersedes any earlier 401 marker
        return cred


def connect_with_pkce(*, flow: str = "loopback", open_browser: bool = True,
                      code_reader=None, store: Optional[ApiKeyAdapter] = None) -> Credential:
    """The complete interactive login, shared by the CLI and the dashboard.

    `code_reader` is called with the authorize URL and must return the pasted code (Flow B);
    when it is None, a loopback callback is waited on (Flow A).
    """
    adapter = PkceAdapter(flow=flow, open_browser=open_browser, store=store)
    session = adapter.start()
    try:
        if flow == "oob":
            code = adapter.submit_code(session, code_reader(session.url) if code_reader else "")
        else:
            code = adapter.wait(session)
        return adapter.finish(session, code)
    finally:
        adapter.cancel()


# ------------------------------------------------------------------- model catalog
@dataclass
class Catalog:
    models: list
    source: str                  # "live" | "seed"      (seed == degraded)
    degraded: bool
    error: str = ""
    capability: str = "chat"

    def ids(self) -> list:
        return [m.get("id") for m in self.models]

    def to_dict(self) -> dict:
        return {"models": self.models, "source": self.source, "degraded": self.degraded,
                "error": self.error, "capability": self.capability,
                "count": len(self.models),
                "catalog_url": api_base_url() + "/models"}


def _seed_models() -> list:
    seed = (PROVIDER.get("verified_seed") or {}).get("models") or []
    out = []
    for m in seed:
        if isinstance(m, dict) and m.get("id"):
            out.append({
                "id": m["id"], "name": m.get("name") or m["id"],
                "context_window": m.get("context_window"),
                "input_modalities": list(m.get("input_modalities") or ["text"]),
                "supported_endpoint_types": list(m.get("supported_endpoint_types") or ["openai"]),
                "reasoning_efforts": m.get("reasoning_efforts"),
                "source": "seed",
            })
    return out


def normalize_model(rec: dict) -> Optional[dict]:
    """One accepted catalog record → the minimal metadata the selectors need. Anything that is
    not a dict with an id is refused: a catalog must not be able to inject shapes we cannot
    speak, and the id keeps its vendor/model namespace EXACTLY as advertised."""
    if not isinstance(rec, dict):
        return None
    mid = rec.get("id")
    if not isinstance(mid, str) or not mid.strip() or len(mid) > 200:
        return None
    arch = rec.get("architecture") if isinstance(rec.get("architecture"), dict) else {}
    modalities = arch.get("input_modalities")
    if not isinstance(modalities, list):
        modalities = rec.get("input_modalities")
    modalities = [m for m in modalities if isinstance(m, str)] if isinstance(modalities, list) else []
    endpoints = rec.get("supported_endpoint_types")
    if not isinstance(endpoints, list):
        endpoints = []
    endpoints = [e for e in endpoints if isinstance(e, str)]
    ctx = rec.get("context_length") or rec.get("context_window")
    efforts = rec.get("reasoning_efforts")
    if not isinstance(efforts, list):
        efforts = None
    return {
        "id": mid.strip(),
        "name": (rec.get("name") if isinstance(rec.get("name"), str) else None) or mid.strip(),
        "context_window": ctx if isinstance(ctx, int) and ctx > 0 else None,
        "input_modalities": modalities,
        "supported_endpoint_types": endpoints,
        "reasoning_efforts": efforts,
        "source": "live",
    }


_CHAT_TYPES = set((PROVIDER.get("catalog") or {}).get("chat_endpoint_types")
                  or ["openai", "anthropic", "gemini", "openai-response"])
_NON_CHAT_TYPES = set((PROVIDER.get("catalog") or {}).get("non_chat_endpoint_types")
                      or ["image-generation", "openai-video", "jina-rerank", "embeddings"])
_PURPOSE_ENDPOINT = {
    "embedding": "embeddings",
    "image": "image-generation",
    "video": "openai-video",
    "rerank": "jina-rerank",
}


def filter_models(models: list, capability: str = "chat",
                  modality: Optional[str] = None) -> list:
    """Per-entry-point capability filter. A model whose metadata does not PROVE compatibility
    is excluded — fail closed. Nothing here is inferred from a model's name."""
    if capability == "chat":
        out = []
        for m in models:
            types = set(m.get("supported_endpoint_types") or [])
            if not (types & _CHAT_TYPES):
                continue
            if types & _NON_CHAT_TYPES and not (types & _CHAT_TYPES):
                continue
            if modality and modality != "text":
                if modality not in (m.get("input_modalities") or []):
                    continue
            out.append(m)
        return out
    want = _PURPOSE_ENDPOINT.get(capability)
    if want:
        return [m for m in models if want in (m.get("supported_endpoint_types") or [])]
    return []                        # an unknown capability proves nothing → empty, not "all"


def fetch_catalog(cred: Optional[Credential] = None, *, capability: str = "chat",
                  modality: Optional[str] = None, timeout: Optional[float] = None,
                  use_cache: bool = True) -> Catalog:
    """Live `GET /v1/models`, bounded, on the INFERENCE origin. On any failure the verified seed
    (or the last known-good catalog) is returned and the result is marked degraded — never a
    free-text model field, and never a merge of seed and live rows."""
    cred = cred if cred is not None else credential()
    bounds = PROVIDER.get("catalog") or {}
    limit_t = float(timeout if timeout is not None else bounds.get("timeout_s", 8))
    max_bytes = int(bounds.get("max_bytes", 2097152))
    max_items = int(bounds.get("max_items", 2000))

    error = ""
    models = []
    if cred is None:
        error = "no OrcaRouter credential configured"
    elif needs_reauth(cred):
        error = "the stored OrcaRouter key was rejected (401) — reauthenticate"
    else:
        req = urllib.request.Request(api_base_url() + "/models", method="GET",
                                     headers={"Authorization": f"Bearer {cred.api_key}",
                                              "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=limit_t) as r:
                raw = r.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raise ValueError("catalog response exceeded the byte ceiling")
            data = json.loads(raw.decode("utf-8"))
            rows = data.get("data") if isinstance(data, dict) else data
            if not isinstance(rows, list):
                raise ValueError("catalog response has no data array")
            for rec in rows[:max_items]:
                norm = normalize_model(rec)
                if norm is not None:
                    models.append(norm)
            if not models:
                raise ValueError("catalog returned no usable models")
            _write_last_known_good(models)
        except urllib.error.HTTPError as e:
            error = f"catalog request failed ({e.code})"
            if e.code == 401:
                mark_unauthorized(cred.generation)
        except (urllib.error.URLError, OSError, ValueError, UnicodeDecodeError) as e:
            error = f"catalog unavailable ({type(e).__name__})"
        models = [m | {"source": "live"} for m in models] if models else []

    if models:
        return Catalog(models=filter_models(models, capability, modality), source="live",
                       degraded=False, capability=capability)

    fallback = _read_last_known_good() if use_cache else []
    source = "seed"
    if fallback:
        source = "last_known_good"
    rows = filter_models(fallback or _seed_models(), capability, modality)
    return Catalog(models=rows, source=source, degraded=True, error=error,
                   capability=capability)


def _lkg_path() -> str:
    return os.path.join(ENGINE, "MEMORY", "orcarouter_catalog.json")


def _write_last_known_good(models: list) -> None:
    try:
        path = _lkg_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"ts": time.time(), "models": models[:500]}, f)
    except OSError:
        pass


def _read_last_known_good() -> list:
    try:
        with open(_lkg_path(), encoding="utf-8") as f:
            rows = json.load(f).get("models") or []
        return [r for r in rows if isinstance(r, dict) and r.get("id")]
    except (OSError, ValueError):
        return []


def model_for_tier(tier: Optional[str] = None) -> str:
    """Tier → concrete id. The provider default is `orcarouter/auto`; HARNESS_MODEL_MAP still
    overrides per deployment, exactly as it does for every other OpenAI-compatible backend."""
    table = {k: v for k, v in (PROVIDER.get("tier_model_map") or {}).items()
             if not k.startswith("_") and isinstance(v, str)}
    raw = os.environ.get("HARNESS_MODEL_MAP")
    if raw:
        try:
            override = json.loads(raw)
            if isinstance(override, dict):
                table.update({k: v for k, v in override.items() if isinstance(v, str)})
        except ValueError:
            pass
    return table.get(tier or "", PROVIDER.get("default_model") or "orcarouter/auto")


def provider_summary() -> dict:
    """What the CLI and the dashboard show for this provider. Never includes the key."""
    cred = credential()
    return {
        "id": PROVIDER_ID,
        "label": PROVIDER.get("label") or LABEL,
        "api_base_url": api_base_url(),
        "auth_base_url": auth_base_url(),
        "authorize_url": authorize_url(),
        "exchange_url": exchange_url(),
        "console_url": PROVIDER.get("console_url"),
        "provider_page": PROVIDER.get("provider_page"),
        "cyber_catalog_url": PROVIDER.get("cyber_catalog_url"),
        "default_model": PROVIDER.get("default_model"),
        "fallback_model": PROVIDER.get("fallback_model"),
        "cyber_models": PROVIDER.get("cyber_models") or [],
        "tier_model_map": {k: v for k, v in (PROVIDER.get("tier_model_map") or {}).items()
                           if not k.startswith("_")},
        "credential": None if cred is None else {
            "masked": cred.masked, "source": cred.source, "generation": cred.generation,
            "scope": cred.scope, "needs_reauth": needs_reauth(cred),
        },
    }
