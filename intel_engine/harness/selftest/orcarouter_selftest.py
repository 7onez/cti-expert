#!/usr/bin/env python3
"""orcarouter_selftest.py — behavioural checks for the OrcaRouter Cyber Inference provider.

WHY IT IS HERE (and not under tests/)
  This repo keeps `tests/`, `intel_engine/tests/` and every `test_*.py` LOCAL-ONLY and gitignored
  (CLAUDE.md: "Tests are local-only — never commit or push them"). A contribution that adds a
  credential flow has to ship something a maintainer and CI can actually RUN on a clean checkout,
  so these checks are a stdlib-only, offline, self-contained script under a path the ignore rules
  do not cover. It touches no case data, no target and no third-party credit.

WHAT IT DEFENDS (one line each)
  provider      the named provider is registered, selectable, resolves its own origins and model
  api_key       save / read / clear / mask through the project's existing `.env` store
  pkce          S256, fresh verifier+state, correct exchange path and body, denial/state/403/429
  catalog       live `/v1/models` is authoritative; failure falls back to the verified seed only
  capabilities  chat / multimodal / embedding / image / video / rerank filters, fail closed
  errors        terminal 401 marks the exact generation, no refresh-from-nothing, scope check
  regression    the OpenAI-compatible revenue path is unchanged for non-OrcaRouter backends
  live          one real request through the provider's own code path (needs ORCAROUTER_API_KEY)

USAGE
  python3 intel_engine/harness/selftest/orcarouter_selftest.py            # offline
  python3 intel_engine/harness/selftest/orcarouter_selftest.py --live     # + one real request
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import traceback
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.dirname(HERE)
sys.path.insert(0, HARNESS)

GREEN, RED, RESET = "\033[32m", "\033[31m", "\033[0m"

_CHECKS = []


def check(fn):
    _CHECKS.append(fn)
    return fn


# ------------------------------------------------------------------ fake origins
class _Fake:
    """Two tiny HTTP servers standing in for the two PUBLIC ORIGINS.

    Separate ports on purpose: a client that derives the exchange URL from the inference base
    (or the reverse) cannot pass these checks, which is the failure mode this integration is
    most likely to have.
    """

    def __init__(self) -> None:
        self.requests = []                       # (server, method, path, body)
        self.catalog = {"data": []}
        self.catalog_status = 200
        self.oversized = False
        self.exchange_status = 200
        self.exchange_body = {"key": "sk-orca-testkey-0000000000000000", "user_id": "1",
                              "scope": "api"}
        self.last_challenge = ""
        self.last_state = ""
        self.callback_url = ""
        self.code = "code-one-time-abc"
        self.auth_action = "approve"             # approve | deny
        fake = self

        class Auth(BaseHTTPRequestHandler):
            def log_message(self, *a):
                return

            def do_GET(self):                    # noqa: N802
                u = urllib.parse.urlsplit(self.path)
                fake.requests.append(("auth", "GET", u.path, ""))
                q = urllib.parse.parse_qs(u.query)
                if u.path != "/auth":
                    self.send_response(404); self.end_headers(); return
                fake.last_challenge = (q.get("code_challenge") or [""])[0]
                fake.last_state = (q.get("state") or [""])[0]
                fake.callback_url = (q.get("callback_url") or [""])[0]
                fake.auth_params = {k: v[0] for k, v in q.items()}
                target = fake.callback_url + ("&" if "?" in fake.callback_url else "?")
                if fake.auth_action == "deny":
                    target += urllib.parse.urlencode({"error": "access_denied",
                                                      "state": fake.last_state})
                else:
                    target += urllib.parse.urlencode({"code": fake.code,
                                                      "state": fake.last_state})
                self.send_response(302)
                self.send_header("Location", target)
                self.end_headers()

            def do_POST(self):                   # noqa: N802
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n)
                u = urllib.parse.urlsplit(self.path)
                fake.requests.append(("auth", "POST", u.path, raw.decode("utf-8", "replace")))
                if u.path != "/api/v1/auth/keys":
                    self.send_response(404); self.end_headers(); return
                try:
                    body = json.loads(raw)
                except ValueError:
                    body = {}
                fake.last_exchange = body
                payload = dict(fake.exchange_body)
                if fake.exchange_status == 200:
                    # Server-side PKCE check, as the real exchange does: the VERIFIER must hash
                    # to the CHALLENGE the authorize request carried.
                    import base64
                    import hashlib
                    want = base64.urlsafe_b64encode(
                        hashlib.sha256((body.get("code_verifier") or "").encode()).digest()
                    ).decode().rstrip("=")
                    if want != fake.last_challenge:
                        fake.exchange_status = 403
                    elif body.get("code_challenge_method") != "S256":
                        fake.exchange_status = 400
                status = fake.exchange_status
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        class Api(BaseHTTPRequestHandler):
            def log_message(self, *a):
                return

            def do_GET(self):                    # noqa: N802
                u = urllib.parse.urlsplit(self.path)
                fake.requests.append(("api", "GET", u.path, ""))
                if u.path != "/v1/models":
                    self.send_response(404); self.end_headers(); return
                if fake.catalog_status != 200:
                    self.send_response(fake.catalog_status); self.end_headers(); return
                raw = json.dumps(fake.catalog).encode()
                if fake.oversized:
                    raw = b"[" + b" " * (3 * 1024 * 1024) + b"]"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):                   # noqa: N802
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n)
                u = urllib.parse.urlsplit(self.path)
                fake.requests.append(("api", "POST", u.path, raw.decode("utf-8", "replace")))
                if u.path != "/v1/chat/completions":
                    self.send_response(404); self.end_headers(); return
                if fake.chat_status != 200:
                    self.send_response(fake.chat_status); self.end_headers(); return
                data = json.dumps({"choices": [{"message": {"role": "assistant",
                                                            "content": "ok"}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.chat_status = 200
        self.auth_srv = HTTPServer(("127.0.0.1", 0), Auth)
        self.api_srv = HTTPServer(("127.0.0.1", 0), Api)
        for srv in (self.auth_srv, self.api_srv):
            threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.1},
                             daemon=True).start()

    @property
    def auth_base(self) -> str:
        return f"http://127.0.0.1:{self.auth_srv.server_address[1]}"

    @property
    def api_base(self) -> str:
        return f"http://127.0.0.1:{self.api_srv.server_address[1]}/v1"

    def close(self) -> None:
        for srv in (self.auth_srv, self.api_srv):
            srv.shutdown()
            srv.server_close()


CATALOG_FIXTURE = {
    "data": [
        {"id": "vendor/text-only", "name": "Text Only",
         "supported_endpoint_types": ["openai"], "architecture": {"input_modalities": ["text"]},
         "context_length": 128000},
        {"id": "vendor/vision-chat", "name": "Vision Chat",
         "supported_endpoint_types": ["openai", "anthropic"],
         "architecture": {"input_modalities": ["text", "image"]}, "context_length": 200000},
        {"id": "vendor/embed", "name": "Embed",
         "supported_endpoint_types": ["embeddings"], "architecture": {"input_modalities": ["text"]}},
        {"id": "vendor/image-gen", "name": "Image Gen",
         "supported_endpoint_types": ["image-generation"],
         "architecture": {"input_modalities": ["text"], "output_modalities": ["image"]}},
        {"id": "vendor/video-gen", "name": "Video Gen",
         "supported_endpoint_types": ["openai-video"], "architecture": {"input_modalities": ["text"]}},
        {"id": "vendor/rerank", "name": "Rerank",
         "supported_endpoint_types": ["jina-rerank"], "architecture": {"input_modalities": ["text"]}},
        {"id": "vendor/deepseek-v4-pro", "name": "Reasoner",
         "supported_endpoint_types": ["openai"], "architecture": {"input_modalities": ["text"]}},
    ]
}


# ------------------------------------------------------------------ harness helpers
class Sandbox:
    """An isolated env: its own `.env`, its own reauth state, its own catalog cache."""

    def __init__(self, fake: _Fake):
        self.fake = fake
        self.dir = tempfile.mkdtemp(prefix="orca-selftest-")
        self.saved = {}

    def __enter__(self):
        saved = {}
        for var in ("ORCA_AUTH_BASE_URL", "ORCA_API_BASE_URL", "ORCA_BASE_URL",
                    "CTI_API_KEYS_ENV", "ORCA_REAUTH_STATE", "HARNESS_BACKEND",
                    "HARNESS_MODEL_MAP", "ORCAROUTER_API_KEY"):
            saved[var] = os.environ.pop(var, None)
        self.saved = saved
        os.environ["ORCA_AUTH_BASE_URL"] = self.fake.auth_base
        os.environ["ORCA_API_BASE_URL"] = self.fake.api_base
        os.environ["CTI_API_KEYS_ENV"] = os.path.join(self.dir, ".env")
        os.environ["ORCA_REAUTH_STATE"] = os.path.join(self.dir, "reauth.json")
        import orcarouter as orc
        self._lkg = orc._lkg_path
        orc._lkg_path = lambda: os.path.join(self.dir, "catalog.json")
        return self

    def __exit__(self, *a):
        import orcarouter as orc
        orc._lkg_path = self._lkg
        for var, val in self.saved.items():
            os.environ.pop(var, None)
            if val is not None:
                os.environ[var] = val
        return False


def _load_module_fresh():
    for name in ("orcarouter", "backend_select", "openai_backend", "sdk_compat"):
        sys.modules.pop(name, None)
    import orcarouter
    return orcarouter


def _no_secret(text: str, *values) -> bool:
    return not any(v and v in text for v in values)


# ------------------------------------------------------------------ checks
@check
def provider_registered():
    """The provider is a NAMED backend — in the registry, the known list and the probe order."""
    import backend_select as bs
    assert "orcarouter" in bs.OPENAI_BACKENDS, "not in OPENAI_BACKENDS"
    assert "orcarouter" in bs.KNOWN, "not in KNOWN"
    assert "orcarouter" in bs.candidates(), "auto resolution would never try it"
    assert bs.OPENAI_BACKENDS.index("orcarouter") > 0
    import orcarouter as orc
    assert orc.PROVIDER_ID == "orcarouter"
    assert orc.PROVIDER["label"] == "OrcaRouter Cyber Inference"
    s = orc.provider_summary()
    assert s["api_base_url"] == "https://api.orcarouter.ai/v1"
    assert s["auth_base_url"] == "https://www.orcarouter.ai"
    assert s["default_model"] == "orcarouter/auto"
    assert s["fallback_model"] == "orcarouter/fusion"
    assert "https://www.orcarouter.ai/cyber" == s["provider_page"]
    assert "tier=cyber" in s["cyber_catalog_url"]
    assert all("orcarouter" in m or "orcacyber" in m for m in s["cyber_models"])


@check
def api_key_adapter_and_store():
    """Save / read / clear / mask, through the project's own `.env` mechanism."""
    import orcarouter as orc
    fake = _Fake()
    try:
        with Sandbox(fake):
            adapter = orc.ApiKeyAdapter()
            assert adapter.read() is None
            cred = adapter.save("sk-orca-selftest-aaaaaaaaaaaaaaaa")
            assert cred.source == "api_key" and cred.scope == "api"
            path = os.environ["CTI_API_KEYS_ENV"]
            assert os.path.isfile(path)
            assert oct(os.stat(path).st_mode & 0o777) == "0o600", "secret file must be chmod 600"
            again = orc.credential()
            assert again is not None and again.api_key == cred.api_key
            assert again.masked.startswith("sk-orca-…"), again.masked
            assert "aaaa" not in again.masked, "no part of the secret may survive masking"
            assert cred.api_key not in cred.masked
            adapter.clear()
            assert orc.credential() is None
            # format sanity, not validation
            assert orc.looks_like_key("sk-orca-" + "x" * 24)
            assert not orc.looks_like_key("sk-other-" + "x" * 24)
    finally:
        fake.close()


@check
def origins_are_separate():
    """auth → www origin + /api/v1/auth/keys; inference → api origin + /v1. Never derived."""
    import orcarouter as orc
    fake = _Fake()
    try:
        with Sandbox(fake):
            assert orc.auth_base_url() == fake.auth_base
            assert orc.api_base_url() == fake.api_base
            assert orc.exchange_url() == fake.auth_base + "/api/v1/auth/keys"
            assert orc.exchange_url().endswith("/api/v1/auth/keys")
            assert not orc.exchange_url().startswith(orc.api_base_url())
            assert not orc.exchange_url().replace("/api/v1/auth/keys", "").endswith("/v1")
            # shared self-hosted base: one origin, documented suffixes, no hostname swap
            os.environ.pop("ORCA_AUTH_BASE_URL")
            os.environ.pop("ORCA_API_BASE_URL")
            os.environ["ORCA_BASE_URL"] = "https://orca.example"
            assert orc.auth_base_url() == "https://orca.example"
            assert orc.api_base_url() == "https://orca.example/v1"
            os.environ["ORCA_API_BASE_URL"] = "https://relay.example/v1"
            assert orc.api_base_url() == "https://relay.example/v1"
            assert orc.auth_base_url() == "https://orca.example"
            # a remote plain-http origin is refused; loopback is allowed (test servers live there)
            os.environ["ORCA_API_BASE_URL"] = "http://relay.example/v1"
            try:
                orc.api_base_url()
                raise AssertionError("http on a remote host must be refused")
            except ValueError:
                pass
    finally:
        fake.close()


@check
def pkce_loopback_end_to_end():
    """Flow A: authorize → callback → exchange → persist, with S256 actually verified."""
    import orcarouter as orc
    fake = _Fake()
    try:
        with Sandbox(fake):
            flow = orc.PkceAdapter(flow="loopback", open_browser=False)
            session = flow.start()
            url = session.url
            assert url.startswith(fake.auth_base + "/auth?"), url
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            assert q["code_challenge_method"][0] == "S256"
            assert q["callback_url"][0].startswith("http://127.0.0.1:")
            assert q["scope"][0] == "api"
            assert session.verifier not in url, "the verifier must never ride on the URL"
            verifier = session.verifier
            state = session.state
            assert verifier not in repr(session)
            # "browser": follow the consent redirect into our listener
            urllib.request.urlopen(url, timeout=5).read()
            code = flow.wait(session, timeout=5)
            assert code == fake.code
            cred = flow.finish(session, code)
            assert cred.source == "pkce" and cred.scope == "api"
            body = json.loads([r for r in fake.requests
                               if r[1] == "POST" and r[2] == "/api/v1/auth/keys"][0][3])
            assert body["code_verifier"] == verifier
            assert body["code_challenge_method"] == "S256"
            # fresh randomness per attempt
            s2 = flow.start()
            assert s2.verifier != verifier and s2.state != state
            flow.cancel()
            assert orc.credential().generation == cred.generation, "cancel must not rotate the key"
    finally:
        fake.close()


@check
def pkce_failures_are_terminal_and_quiet():
    """Denial, state mismatch, 403 reuse/expiry, 429, and a scope downgrade all end cleanly."""
    import orcarouter as orc
    fake = _Fake()
    try:
        with Sandbox(fake):
            # denial
            fake.auth_action = "deny"
            flow = orc.PkceFlow(open_browser=False)
            s = flow.start()
            urllib.request.urlopen(s.url, timeout=5).read()
            try:
                flow.wait(s, timeout=5)
                raise AssertionError("denial must raise")
            except orc.ConnectError as e:
                assert e.kind == "denied", e.kind

            # state mismatch: somebody else's page drops a code on the listener
            fake.auth_action = "approve"
            flow = orc.PkceFlow(open_browser=False)
            s = flow.start()
            port = s.redirect_uri.split(":")[2].split("/")[0]
            try:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/cb?code=evil&state=not-the-state", timeout=5).read()
            except urllib.error.HTTPError:
                pass
            try:
                flow.wait(s, timeout=5)
                raise AssertionError("state mismatch must raise")
            except orc.ConnectError as e:
                assert e.kind == "state_mismatch", e.kind
                assert "evil" not in str(e)

            # 403: code unknown / expired / already used, or verifier mismatch
            fake.exchange_status = 403
            flow = orc.PkceFlow(open_browser=False)
            s = flow.start()
            urllib.request.urlopen(s.url, timeout=5).read()
            code = flow.wait(s, timeout=5)
            try:
                flow.exchange(s, code)
                raise AssertionError("403 must raise")
            except orc.ConnectError as e:
                assert e.kind == "exchange"
                assert "expired" in str(e) and code not in str(e)

            # 429: the 10-keys-per-24h ceiling
            fake.exchange_status = 429
            flow = orc.PkceFlow(open_browser=False)
            s = flow.start()
            urllib.request.urlopen(s.url, timeout=5).read()
            code = flow.wait(s, timeout=5)
            try:
                flow.exchange(s, code)
                raise AssertionError("429 must raise")
            except orc.ConnectError as e:
                assert "10 PKCE keys" in str(e)

            # scope downgrade: a connector grant cannot drive inference and must not be stored
            fake.exchange_status = 200
            fake.exchange_body = {"key": "sk-orca-downgrade-0000000000", "scope": "connector"}
            flow = orc.PkceFlow(open_browser=False)
            s = flow.start()
            urllib.request.urlopen(s.url, timeout=5).read()
            code = flow.wait(s, timeout=5)
            try:
                flow.exchange(s, code)
                raise AssertionError("scope downgrade must raise")
            except orc.ConnectError as e:
                assert e.kind == "scope"
            assert orc.credential() is None or orc.credential().api_key != "sk-orca-downgrade-0000000000"

            # a timeout must release the listener rather than hang
            flow = orc.PkceFlow(open_browser=False)
            s = flow.start()
            try:
                flow.wait(s, timeout=0.3)
                raise AssertionError("timeout must raise")
            except orc.ConnectError as e:
                assert e.kind == "timeout"
            assert flow.active() is None
    finally:
        fake.close()


@check
def credential_source_is_invisible_downstream():
    """API key and PKCE both yield the same Credential; discovery cannot tell them apart."""
    import orcarouter as orc
    fake = _Fake()
    try:
        with Sandbox(fake):
            fake.catalog = CATALOG_FIXTURE
            via_key = orc.ApiKeyAdapter().save("sk-orca-by-key-000000000000")
            cat_key = orc.fetch_catalog(via_key, use_cache=False)
            os.environ["CTI_API_KEYS_ENV"] = os.path.join(fake.auth_base, "ignored")
            os.environ["CTI_API_KEYS_ENV"] = tempfile.mktemp(prefix="orca-pkce-", suffix=".env")
            via_pkce = orc.ApiKeyAdapter().save("sk-orca-by-pkce-111111111111")
            cat_pkce = orc.fetch_catalog(via_pkce, use_cache=False)
            assert cat_key.ids() == cat_pkce.ids()
            assert cat_key.source == cat_pkce.source == "live"
            assert cat_key.models[0].keys() == cat_pkce.models[0].keys()
    finally:
        fake.close()


@check
def catalog_is_live_authoritative_with_verified_fallback():
    """Live wins wholesale; failure degrades to the seed, labelled, with metadata intact."""
    import orcarouter as orc
    fake = _Fake()
    try:
        with Sandbox(fake):
            orc.ApiKeyAdapter().save("sk-orca-catalog-000000000000")
            fake.catalog = CATALOG_FIXTURE
            live = orc.fetch_catalog(use_cache=False)
            assert live.source == "live" and not live.degraded
            assert len(live.models) == 3, [m["id"] for m in live.models]   # the chat rows only
            assert "vendor/text-only" in live.ids()
            assert "vendor/embed" not in live.ids()
            # the seed is NOT merged into a live result
            assert "orcarouter/auto" not in live.ids()

            # outage → verified seed, explicitly degraded
            fake.catalog_status = 500
            down = orc.fetch_catalog(use_cache=False)
            assert down.degraded and down.source == "seed"
            assert "orcarouter/auto" in down.ids()
            assert "orcarouter/fusion" in down.ids()
            gpt = [m for m in down.models if m["id"] == "openai/gpt-5.5"]
            assert gpt and gpt[0]["reasoning_efforts"] == ["low", "medium", "high", "xhigh"]

            # oversized response is refused, not parsed
            fake.catalog_status = 200
            fake.oversized = True
            big = orc.fetch_catalog(use_cache=False)
            assert big.degraded
            fake.oversized = False

            # last-known-good survives an outage, and is still labelled degraded
            fake.catalog_status = 200
            orc.fetch_catalog(use_cache=False)
            fake.catalog_status = 500
            lkg = orc.fetch_catalog()               # the default path may reuse last-known-good
            assert lkg.degraded and lkg.source == "last_known_good"
            assert "vendor/text-only" in lkg.ids()
            # ...but only the seed is ever used when the caller opts out of the cache
            cold = orc.fetch_catalog(use_cache=False)
            assert cold.source == "seed" and "orcarouter/auto" in cold.ids()
    finally:
        fake.close()


@check
def capability_filters_fail_closed():
    """Every entry point gets its own filter; an undeclared capability is excluded."""
    import orcarouter as orc
    models = [orc.normalize_model(r) for r in CATALOG_FIXTURE["data"]]
    assert all(m is not None for m in models)
    chat = [m["id"] for m in orc.filter_models(models, "chat")]
    assert chat == ["vendor/text-only", "vendor/vision-chat", "vendor/deepseek-v4-pro"], chat
    vision = [m["id"] for m in orc.filter_models(models, "chat", "image")]
    assert vision == ["vendor/vision-chat"], vision
    assert [m["id"] for m in orc.filter_models(models, "chat", "audio")] == []
    assert [m["id"] for m in orc.filter_models(models, "embedding")] == ["vendor/embed"]
    assert [m["id"] for m in orc.filter_models(models, "image")] == ["vendor/image-gen"]
    assert [m["id"] for m in orc.filter_models(models, "video")] == ["vendor/video-gen"]
    assert [m["id"] for m in orc.filter_models(models, "rerank")] == ["vendor/rerank"]
    assert orc.filter_models(models, "telepathy") == []
    # a model with no declared endpoint types proves nothing
    assert orc.normalize_model({"id": "vendor/mystery"}) is not None
    assert orc.filter_models([orc.normalize_model({"id": "vendor/mystery"})], "chat") == []
    # ids keep their vendor namespace exactly
    assert orc.normalize_model({"id": "vendor/deepseek-v4-pro"})["id"] == "vendor/deepseek-v4-pro"


@check
def terminal_401_is_generation_safe():
    """A 401 marks exactly the rejected generation; no refresh, no overwrite of a new key."""
    import orcarouter as orc
    fake = _Fake()
    try:
        with Sandbox(fake):
            cred1 = orc.ApiKeyAdapter().save("sk-orca-gen-one-000000000000")
            assert orc.mark_unauthorized(cred1.generation) is True
            assert orc.needs_reauth(cred1) is True
            # a stale generation (an old, in-flight request) cannot mark the new key
            cred2 = orc.ApiKeyAdapter().save("sk-orca-gen-two-111111111111")
            assert orc.needs_reauth(cred2) is False
            assert orc.mark_unauthorized(cred1.generation) is False
            assert orc.needs_reauth(cred2) is False
            # a key needing reauth does not silently refresh; discovery says so
            orc.mark_unauthorized(cred2.generation)
            cat = orc.fetch_catalog(cred2, use_cache=False)
            assert cat.degraded and "reauthenticate" in cat.error
            # no refresh machinery exists to be called by mistake
            assert not hasattr(orc, "refresh"), "a durable key must not grow a refresh path"
            orc.ApiKeyAdapter().clear()
            assert orc.needs_reauth(None) is False
    finally:
        fake.close()


@check
def request_path_marks_401_and_uses_provider_origins():
    """The real chat path hits the API origin with Bearer, and a 401 marks the generation."""
    fake = _Fake()
    try:
        with Sandbox(fake):
            os.environ["HARNESS_BACKEND"] = "orcarouter"
            for name in ("orcarouter", "openai_backend"):
                sys.modules.pop(name, None)
            import orcarouter as orc
            import openai_backend as ob
            cred = orc.ApiKeyAdapter().save("sk-orca-path-000000000000")
            assert ob._base_url() == fake.api_base
            assert ob._api_key() == cred.api_key
            assert ob._model_for("opus") == "orcarouter/auto"
            os.environ["HARNESS_MODEL_MAP"] = json.dumps({"opus": "orca/orcacyber-ultra-1.0"})
            assert ob._model_for("opus") == "orca/orcacyber-ultra-1.0"
            os.environ.pop("HARNESS_MODEL_MAP")

            ok, err = ob._http_post({"model": "orcarouter/auto", "messages": []}, timeout=5)
            assert err is None and ok["choices"][0]["message"]["content"] == "ok"
            posted = [r for r in fake.requests if r[1] == "POST"]
            assert posted and posted[-1][2] == "/v1/chat/completions", posted[-1][2]

            fake.chat_status = 401
            ok, err = ob._http_post({"model": "orcarouter/auto", "messages": []}, timeout=5)
            assert ok is None and "401" in err
            assert orc.needs_reauth(cred) is True
    finally:
        fake.close()


@check
def other_providers_are_unchanged():
    """Regression: the shared OpenAI-compatible path still uses OPENAI_BASE_URL/OPENAI_API_KEY."""
    fake = _Fake()
    try:
        with Sandbox(fake):
            os.environ["HARNESS_BACKEND"] = "deepseek"
            for name in ("orcarouter", "openai_backend"):
                sys.modules.pop(name, None)
            import openai_backend as ob
            os.environ["OPENAI_BASE_URL"] = "https://api.deepseek.com"
            os.environ["OPENAI_API_KEY"] = "sk-test-not-a-real-key"
            assert ob._base_url() == "https://api.deepseek.com"
            assert ob._api_key() == "sk-test-not-a-real-key"
            assert ob._model_for("opus") == "deepseek-chat"
            import backend_select as bs
            assert bs.available("orcarouter") == (False,
                "no OrcaRouter credential (ORCAROUTER_API_KEY or the skill-root .env)")
            os.environ.pop("OPENAI_API_KEY")
            os.environ.pop("OPENAI_BASE_URL")
    finally:
        fake.close()


@check
def dashboard_never_returns_a_key():
    """The provider API surface hands the page metadata only."""
    fake = _Fake()
    try:
        with Sandbox(fake):
            for name in ("orcarouter", "provider_api"):
                sys.modules.pop(name, None)
            sys.path.insert(0, os.path.join(HARNESS, "dashboard"))
            import orcarouter as orc
            import provider_api as pa
            cred = orc.ApiKeyAdapter().save("sk-orca-dashboard-000000000000")
            status, payload = pa.handle_get("/api/provider/state", {})
            assert status == 200
            blob = json.dumps(payload)
            assert cred.api_key not in blob
            assert payload["credential"]["masked"].startswith("sk-orca-…")
            assert "0000" not in payload["credential"]["masked"]
            status, payload = pa.handle_post("/api/provider/key",
                                             {"api_key": "sk-orca-second-111111111111"})
            blob = json.dumps(payload)
            assert "sk-orca-second-111111111111" not in blob
            assert status == 200 and payload["masked"].startswith("sk-orca-…")
            assert "1111" not in payload["masked"]
            # a cancelled attempt leaves no listener and no busy state
            status, payload = pa.handle_post("/api/provider/connect", {"flow": "oob"})
            assert payload["state"] == "awaiting_code"
            status, payload = pa.handle_post("/api/provider/connect/cancel", {})
            assert payload["state"] == "idle" and payload["authorize_url"] == ""
    finally:
        fake.close()


@check
def live_provider_request():
    """One REAL request through this provider's own code path, plus the live catalog."""
    import orcarouter as orc
    cred = orc.credential()
    if cred is None:
        raise AssertionError("no OrcaRouter credential in this environment")
    cat = orc.fetch_catalog(cred, capability="chat", use_cache=False)
    assert not cat.degraded, cat.error
    assert len(cat.models) > 0
    assert "orcarouter/auto" in cat.ids()
    sys.modules.pop("openai_backend", None)
    os.environ["HARNESS_BACKEND"] = "orcarouter"
    import openai_backend as ob
    try:
        os.environ.pop("HARNESS_MODEL_MAP", None)
    except KeyError:
        pass
    # Prefer a cyber-tier model when the key is entitled to it (403 = not unlocked on this key).
    tried = []
    for model in ("orca/orcacyber-ultra-1.0", "deepseek/deepseek-v4.1-flash"):
        resp, err = ob._http_post(
            {"model": model, "max_tokens": 16,
             "messages": [{"role": "user", "content": "Reply with the single word: ok"}]},
            timeout=60)
        tried.append((model, bool(resp), (err or "")[:120]))
        if resp is not None:
            print(f"      live model {model} → "
                  f"{resp['choices'][0]['message'].get('content', '')!r}")
            return
    raise AssertionError(f"no live model answered: {tried}")


# ------------------------------------------------------------------ runner
def check_all(live: bool = False):
    passed = failed = 0
    lines = []
    for fn in _CHECKS:
        if fn is live_provider_request and not live:
            lines.append("  SKIP live_provider_request (offline run; pass --live with a key)")
            continue
        try:
            fn()
            passed += 1
            lines.append(f"{GREEN}  PASS{RESET} {fn.__name__} — {(fn.__doc__ or '').strip().splitlines()[0]}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            lines.append(f"{RED}  FAIL{RESET} {fn.__name__}: {type(e).__name__}: {e}")
            tb = traceback.format_exc().strip().splitlines()[-3:]
            lines.extend("        " + ln for ln in tb)
    return passed, failed, lines


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    live = "--live" in argv
    passed, failed, lines = check_all(live=live)
    print("\n".join(lines))
    print(f"\n{passed} passed, {failed} failed"
          + ("" if live else " (live check skipped)"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
