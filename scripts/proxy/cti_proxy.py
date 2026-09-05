#!/usr/bin/env python3
"""
cti_proxy.py — shared egress-proxy layer for the cti-expert skill (the `/proxy`
runtime).

WHY THIS EXISTS
  Every collector in this skill makes outbound HTTP with the stdlib
  `urllib.request.urlopen` (bare — using the process-global default opener).
  Installing ONE global opener here therefore routes *all* of those calls —
  keyless crt.sh, Wayback/CDX, urlscan, the CLD connector, WHOIS, analytics-ID
  reverses, every `/apikeys test` probe — through a configured proxy, with no
  edit at each call site. Network scripts opt in with a tiny bootstrap that
  imports this module and calls `install()` once at startup.

WHAT IT SUPPORTS
  - A single proxy, or a POOL of rotation proxies (residential / datacenter).
  - Rotation policies: round-robin (persisted across invocations), random,
    sticky (pin one until it dies), off (first only).
  - Automatic in-process FAILOVER — a dead proxy is skipped and the request is
    retried through the next one; an origin HTTP error (4xx/5xx) is NOT retried
    (the proxy worked, the server answered).
  - A default request TIMEOUT (CTI_PROXY_TIMEOUT, 20s) so a slow/hanging proxy
    fails over instead of blocking forever, plus a per-proxy failure COOLDOWN
    (CTI_PROXY_COOLDOWN, 90s) that deprioritizes a just-failed exit next request.
  - `no_proxy` host bypass and an optional `allow_direct` last resort.
  - HTTP/HTTPS proxies natively; SOCKS4/5 when PySocks is installed.

CONFIG (merged, highest precedence first)
  1. env  CTI_PROXIES (comma/space/newline list) or CTI_PROXY (single)
  2. env  HTTPS_PROXY / HTTP_PROXY / ALL_PROXY (standard, already-in-env)
  3. file scripts/proxy/proxies.json  (managed by `proxy.py`, gitignored)
  Toggles: CTI_PROXY_ENABLED=0|1, CTI_PROXY_ROTATION=<mode>,
           CTI_PROXY_ALLOW_DIRECT=0|1, NO_PROXY=<csv>,
           CTI_PROXY_TIMEOUT=<sec>, CTI_PROXY_COOLDOWN=<sec>.

Stdlib-only. Importable AND runnable (`python3 cti_proxy.py status|pick|test`).
FOR AUTHORIZED INVESTIGATIONS ONLY.
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
import base64
import functools
import json
import os
import random
import socket
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlsplit, quote

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
ENV_PATH = os.environ.get("CTI_API_KEYS_ENV") or os.path.join(SKILL_ROOT, ".env")
STORE_PATH = os.environ.get("CTI_PROXY_STORE") or os.path.join(HERE, "proxies.json")
STATE_PATH = os.path.join(HERE, ".rotation-state")
# Vendor / index API hosts (reference DATA — scripts/proxy/vendor_hosts.json). When EVERY exit
# refuses the CONNECT tunnel to one of these, the block is at the provider, per destination: the
# request goes DIRECT for that host only (a vendor sees a licensed key, not the analyst-vs-target
# relationship the pool protects). The fallback list is the conservative minimum.
_VENDOR_FALLBACK = ["fofa.info", "en.fofa.info", "api.shodan.io", "search.censys.io", "crt.sh"]


@functools.lru_cache(maxsize=1)
def vendor_hosts():
    """The vendor/index API host set — read once per process (this runs inside the failover loop)."""
    try:
        with open(os.path.join(HERE, "vendor_hosts.json"), encoding="utf-8") as f:
            hs = json.load(f).get("direct_fallback_hosts") or []
        return {str(h).strip().lower() for h in hs if str(h).strip()} or set(_VENDOR_FALLBACK)
    except Exception:
        return set(_VENDOR_FALLBACK)


def is_vendor_host(host):
    h = (host or "").lower()
    return any(h == v or h.endswith("." + v) for v in vendor_hosts())


def is_tunnel_refusal(exc):
    """A proxy answered the CONNECT with a non-200 (5xx/4xx) — the exit is up but this DESTINATION
    is refused. Not a dead exit: must not quarantine it, and for a vendor host may go direct."""
    s = str(exc)
    return "Tunnel connection failed" in s or "proxy CONNECT refused" in s


HEALTH_PATH = os.environ.get("CTI_PROXY_HEALTH") or os.path.join(HERE, ".proxy-health")

VALID_SCHEMES = ("http", "https", "socks4", "socks5", "socks5h")
DEFAULT_TEST_URL = "https://api.ipify.org?format=json"
_TRUE = ("1", "true", "yes", "on")
_FALSE = ("0", "false", "no", "off")
# Slow-proxy guard + runtime health. A bare urlopen() passes no timeout, so a
# hanging proxy would block forever; apply this default when the caller gives
# none. And quarantine a proxy that just failed/timed-out for a cooldown window
# so it is not retried first on every subsequent request. Both are env-tunable.
DEFAULT_PROXY_TIMEOUT = 20     # seconds; override via CTI_PROXY_TIMEOUT (<=0 = none)
DEFAULT_PROXY_COOLDOWN = 90    # seconds; override via CTI_PROXY_COOLDOWN (0 disables)

_INSTALLED = False   # guard: install() is idempotent within a process


# ───────────────────────────────────────────────────────── env / config load
def load_env_file(path=ENV_PATH):
    """Merge KEY=VALUE lines from the skill .env into os.environ (never clobber
    a value already exported)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k and v and k not in os.environ:
                    os.environ[k] = v
    except OSError:
        pass


def load_store(path=STORE_PATH):
    """Read the managed proxy store; return a normalized config dict."""
    cfg = {
        "enabled": True,
        "rotation": "round-robin",
        "allow_direct": False,
        "test_url": DEFAULT_TEST_URL,
        "no_proxy": ["localhost", "127.0.0.1", "::1"],
        "proxies": [],
    }
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            cfg.update({k: data[k] for k in cfg if k in data})
    except (OSError, ValueError):
        pass
    # normalize proxy entries to dicts
    norm = []
    for p in cfg.get("proxies") or []:
        if isinstance(p, str):
            p = {"url": p}
        if isinstance(p, dict) and p.get("url"):
            p.setdefault("label", "")
            p.setdefault("enabled", True)
            p.setdefault("added", "")
            p.setdefault("last_ok", None)
            norm.append(p)
    cfg["proxies"] = norm
    return cfg


def save_store(cfg, path=STORE_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)   # may contain proxy credentials
    except OSError:
        pass


def _valid_port(s):
    return s.isdigit() and 1 <= int(s) <= 65535


def _from_shorthand(raw):
    """Expand a provider colon-shorthand to a proxy URL:
         host:port                -> http://host:port
         host:port:user:pass      -> http://user:pass@host:port  (common export)
         user:pass:host:port      -> http://user:pass@host:port  (port auto-detected)
    The 4-token form is ambiguous when the password is all digits, so the tie
    breaks toward the dominant `host:port:user:pass` whenever token[1] is a VALID
    port (1-65535); only a non-port token[1] falls back to `user:pass:host:port`.
    A numeric password can therefore never be mistaken for the port.
    Returns None when it is not a recognizable shorthand."""
    toks = raw.split(":")
    if len(toks) == 2 and _valid_port(toks[1]):
        return f"http://{toks[0]}:{toks[1]}"
    if len(toks) == 4:
        if _valid_port(toks[1]):         # host:port:user:pass (preferred)
            host, port, user, pw = toks
        elif _valid_port(toks[3]):       # user:pass:host:port
            user, pw, host, port = toks
        else:
            return None
        return f"http://{quote(user, safe='')}:{quote(pw, safe='')}@{host}:{port}"
    return None


def normalize_proxy(url):
    """Validate + normalize a proxy URL to scheme://[user:pass@]host:port.
    Accepts, in addition to a full URL:
      - a bare `host:port`                    (http:// assumed)
      - a provider `host:port:user:pass`      shorthand
      - a `user:pass@host:port` authority     (http:// assumed)
      - a pasted `http_proxy="…"` assignment  (prefix + quotes stripped)
    Returns the normalized URL, or None when unusable."""
    url = (url or "").strip()
    if not url:
        return None
    low = url.lower()
    for pfx in ("http_proxy=", "https_proxy=", "all_proxy=", "proxy="):
        if low.startswith(pfx):
            url = url[len(pfx):].strip()
            break
    url = url.strip().strip('"').strip("'").strip()
    if not url:
        return None
    if "://" not in url:
        if "@" in url:                   # user:pass@host:port
            url = "http://" + url
        else:                            # host:port  /  host:port:user:pass
            expanded = _from_shorthand(url)
            if not expanded:
                return None
            url = expanded
    parts = urlsplit(url)
    if parts.scheme not in VALID_SCHEMES or not parts.hostname:
        return None
    try:
        _ = parts.port                   # validates the port is numeric (or absent)
    except ValueError:
        return None
    return url


# ───────────────────────────────────────────────────────── pool assembly
def _split_list(raw):
    out = []
    for tok in raw.replace(",", " ").replace("\n", " ").split():
        n = normalize_proxy(tok)
        if n:
            out.append(n)
    return out


def build_pool(cfg=None):
    """Return the ordered, de-duplicated list of proxy URLs to use, applying the
    env > standard-env > file precedence."""
    cfg = cfg or load_store()
    if os.environ.get("CTI_PROXIES", "").strip():
        pool = _split_list(os.environ["CTI_PROXIES"])
    elif os.environ.get("CTI_PROXY", "").strip():
        pool = _split_list(os.environ["CTI_PROXY"])
    else:
        pool = [normalize_proxy(p["url"]) for p in cfg["proxies"]
                if p.get("enabled", True)]
        pool = [p for p in pool if p]
    if not pool:  # last: honor a pre-existing standard proxy env var
        for var in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy",
                    "HTTP_PROXY", "http_proxy"):
            n = normalize_proxy(os.environ.get(var, ""))
            if n:
                pool = [n]
                break
    seen, dedup = set(), []
    for p in pool:
        if p not in seen:
            seen.add(p)
            dedup.append(p)
    return dedup


def is_enabled(cfg=None):
    v = os.environ.get("CTI_PROXY_ENABLED", "").strip().lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    cfg = cfg or load_store()
    return bool(cfg.get("enabled", True))


def rotation_mode(cfg=None):
    v = os.environ.get("CTI_PROXY_ROTATION", "").strip().lower()
    if v in ("round-robin", "random", "sticky", "off"):
        return v
    cfg = cfg or load_store()
    m = str(cfg.get("rotation", "round-robin")).strip().lower()
    return m if m in ("round-robin", "random", "sticky", "off") else "round-robin"


def allow_direct(cfg=None):
    v = os.environ.get("CTI_PROXY_ALLOW_DIRECT", "").strip().lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    cfg = cfg or load_store()
    return bool(cfg.get("allow_direct", False))

def proxy_timeout():
    """Default per-request timeout (seconds) the failover opener applies when the
    caller passes none. CTI_PROXY_TIMEOUT overrides; <=0 means no default (block
    like stdlib). Invalid values fall back to DEFAULT_PROXY_TIMEOUT."""
    raw = os.environ.get("CTI_PROXY_TIMEOUT", "").strip()
    if not raw:
        return DEFAULT_PROXY_TIMEOUT
    try:
        v = float(raw)
    except ValueError:
        return DEFAULT_PROXY_TIMEOUT
    return v if v > 0 else None


def proxy_cooldown():
    """Seconds to quarantine a proxy after a transport failure/timeout so it is
    tried last on later requests. CTI_PROXY_COOLDOWN overrides; 0 disables."""
    raw = os.environ.get("CTI_PROXY_COOLDOWN", "").strip()
    if not raw:
        return DEFAULT_PROXY_COOLDOWN
    try:
        v = float(raw)
    except ValueError:
        return DEFAULT_PROXY_COOLDOWN
    return max(0.0, v)


def no_proxy_hosts(cfg=None):
    raw = os.environ.get("NO_PROXY") or os.environ.get("no_proxy")
    if raw:
        return [h.strip().lower() for h in raw.split(",") if h.strip()]
    cfg = cfg or load_store()
    return [str(h).strip().lower() for h in (cfg.get("no_proxy") or []) if str(h).strip()]


# ───────────────────────────────────────────────────────── rotation cursor
def _read_cursor():
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            return int(f.read().strip() or "0")
    except (OSError, ValueError):
        return 0


def _write_cursor(n):
    try:
        with open(STATE_PATH, "w", encoding="utf-8") as f:
            f.write(str(int(n)))
    except OSError:
        pass

def _proxy_key(url):
    """Stable, non-secret identity for a proxy: scheme://host:port (credentials
    stripped so they are never written to the on-disk health file)."""
    if not url:
        return None
    p = urlsplit(url)
    host = (p.hostname or "").lower()
    return f"{p.scheme}://{host}:{p.port}" if host else None


def _read_health():
    """Load the persisted proxy-health map {key: last_fail_epoch}. Read fresh on
    every (typically short-lived) run — an in-memory dict would always start empty
    because install() runs once per process."""
    try:
        with open(HEALTH_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {str(k): float(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def _write_health(health):
    try:
        with open(HEALTH_PATH, "w", encoding="utf-8") as f:
            json.dump(health, f)
    except OSError:
        pass


def _mark_bad(url, cooldown):
    """Persist that `url` just failed; prune entries already past cooldown so the
    file stays bounded. No-op when the proxy is direct/None or cooldown disabled."""
    key = _proxy_key(url)
    if not key or not cooldown:
        return
    now = time.time()
    health = {k: ts for k, ts in _read_health().items() if now - ts < cooldown}
    health[key] = now
    _write_health(health)


def _clear_bad(url):
    """Persist that `url` recovered — drop it from the map (writes only when it
    was actually quarantined)."""
    key = _proxy_key(url)
    if not key:
        return
    health = _read_health()
    if key in health:
        del health[key]
        _write_health(health)


def pick_start(pool, mode=None, advance=True):
    """Return the index into `pool` to START from for this run, honoring the
    rotation policy. round-robin persists + advances the on-disk cursor."""
    n = len(pool)
    if n == 0:
        return 0
    mode = mode or rotation_mode()
    if mode == "random":
        return random.randrange(n)
    if mode in ("sticky", "off"):
        return _read_cursor() % n
    # round-robin
    cur = _read_cursor() % n
    if advance:
        _write_cursor((cur + 1) % n)
    return cur


# ───────────────────────────────────────────────────────── failover opener
def _host_of(fullurl):
    url = fullurl.full_url if hasattr(fullurl, "full_url") else fullurl
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _host_bypassed(host, no_proxy):
    for entry in no_proxy:
        e = entry.lstrip(".")
        if host == e or host.endswith("." + e):
            return True
    return False


def _fresh_request(fullurl):
    """urllib's ProxyHandler MUTATES a Request (set_proxy rewrites host/type/_tunnel_host), so a
    Request that failed through exit A would still tunnel through A when retried through B or
    direct. Every attempt gets a clean copy; a bare URL string is returned unchanged."""
    if not isinstance(fullurl, urllib.request.Request):
        return fullurl
    r = urllib.request.Request(fullurl.full_url, data=fullurl.data,
                               headers=dict(fullurl.header_items()),
                               origin_req_host=fullurl.origin_req_host,
                               unverifiable=fullurl.unverifiable, method=fullurl.get_method())
    return r


_VENDOR_DIRECT_NOTED = set()


def _note_vendor_direct(host, exc):
    if host in _VENDOR_DIRECT_NOTED:
        return
    _VENDOR_DIRECT_NOTED.add(host)
    print(f"[cti_proxy] every exit refuses the tunnel to vendor API {host} ({str(exc)[:80]}); "
          f"querying it DIRECT (vendor endpoint, not the target — see proxy/vendor_hosts.json)",
          file=sys.stderr)


class FailoverOpener:
    """Duck-typed opener installed via urllib.request.install_opener(). Bare
    `urlopen(url, data, timeout)` dispatches here. Tries proxies in rotation
    order, failing over on transport errors only."""

    def __init__(self, pool, start, direct_ok, no_proxy):
        self._pool = list(pool)
        self._start = start % len(pool) if pool else 0
        self._direct_ok = direct_ok
        self._no_proxy = no_proxy
        self._cache = {}
        self._timeout = proxy_timeout()      # applied when caller passes none
        self._cooldown = proxy_cooldown()    # quarantine window (persisted to disk)

    def _opener_for(self, proxy):
        if proxy not in self._cache:
            ph = (urllib.request.ProxyHandler({"http": proxy, "https": proxy})
                  if proxy else urllib.request.ProxyHandler({}))
            self._cache[proxy] = urllib.request.build_opener(ph)
        return self._cache[proxy]

    def _order(self, host):
        if self._host_bypassed(host):
            return [None]
        n = len(self._pool)
        rot = [self._pool[(self._start + i) % n] for i in range(n)] if n else []
        if self._cooldown:
            health = _read_health()          # persisted across processes
            now = time.time()
            def _cooling(p):
                ts = health.get(_proxy_key(p))
                return ts is not None and now - ts < self._cooldown
            fresh = [p for p in rot if not _cooling(p)]
            stale = [p for p in rot if _cooling(p)]
            seq = fresh + stale              # quarantined exits still tried, but last
        else:
            seq = rot
        if self._direct_ok or not seq:
            seq = seq + [None]
        return seq

    def _host_bypassed(self, host):
        return bool(host) and _host_bypassed(host, self._no_proxy)

    def open(self, fullurl, data=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        # A bare urlopen() passes the stdlib global-default (no timeout); a
        # hanging proxy would then block forever. Substitute our default so a
        # slow proxy times out and fails over instead.
        if timeout is socket._GLOBAL_DEFAULT_TIMEOUT and self._timeout:
            timeout = self._timeout
        last = None
        host = _host_of(fullurl)
        order = self._order(host)
        refusals = 0                     # exits that answered the CONNECT with a refusal for THIS host
        for proxy in order:
            try:
                resp = self._opener_for(proxy).open(_fresh_request(fullurl), data, timeout)
                if self._cooldown and proxy is not None:
                    _clear_bad(proxy)            # recovered: clear persisted quarantine
                return resp
            except urllib.error.HTTPError as e:
                # 407 = the PROXY rejected auth -> a proxy failure, rotate to the
                # next one. Any other status is the ORIGIN answering (the proxy
                # worked): raise it, and never fan a 403/429 across the whole pool
                # (that burns every exit and hammers the target from many IPs).
                if e.code == 407:
                    _mark_bad(proxy, self._cooldown)
                    last = e
                    continue
                raise
            except Exception as e:  # URLError, socket timeout, proxy CONNECT fail
                if proxy is not None and is_tunnel_refusal(e):
                    # the exit is alive (it answered) — it refuses this DESTINATION. Not the exit's
                    # health, so no quarantine: a per-destination block must not push the whole
                    # pool into cooldown for every other host.
                    refusals += 1
                else:
                    _mark_bad(proxy, self._cooldown)
                last = e
                continue
        proxies_tried = [p for p in order if p is not None]
        if (proxies_tried and refusals == len(proxies_tried) and None not in order
                and is_vendor_host(host)):
            # every exit refuses the tunnel to a VENDOR API host: the block is at the provider, per
            # destination. The pool protects the analyst from the TARGET; a vendor sees a licensed
            # key either way — go direct for this host only. Targets never take this path.
            _note_vendor_direct(host, last)
            return self._opener_for(None).open(_fresh_request(fullurl), data, timeout)
        raise last if last else urllib.error.URLError("no proxy could be reached")


# ───────────────────────────────────────────────────────── SOCKS (optional)
def _install_socks(proxy):
    """Route stdlib sockets through a SOCKS proxy when PySocks is present.
    Returns True on success. Without PySocks, urllib cannot do SOCKS — we leave
    ALL_PROXY set so requests-based tools still honor it, and warn once."""
    try:
        import socks  # type: ignore  (PySocks)
    except Exception:
        print("[cti_proxy] SOCKS proxy configured but PySocks is not installed; "
              "urllib calls will bypass it (install: uv pip install pysocks).",
              file=sys.stderr)
        return False
    parts = urlsplit(proxy)
    stype = socks.SOCKS5 if parts.scheme.startswith("socks5") else socks.SOCKS4
    rdns = parts.scheme == "socks5h"
    socks.set_default_proxy(stype, parts.hostname, parts.port,
                            rdns=rdns, username=parts.username,
                            password=parts.password)
    socket.socket = socks.socksocket
    return True


def proxied_connection(host, port, timeout=15):
    """A raw TLS-able socket to (host, port) that RESPECTS the configured proxy —
    for callers that need a direct socket (e.g. leaf-cert fingerprinting) and would
    otherwise leak the real IP straight to the target.

    Contract, chosen so no caller can silently leak:
      - HTTP/HTTPS proxy set  -> tunnel via CONNECT; on failure RAISE (never direct).
      - SOCKS proxy set       -> return None ONLY when the in-process PySocks hook is
                                 active (CTI_PROXY_SOCKS_ACTIVE=1), so the caller's
                                 plain socket is already routed. If a SOCKS pool is
                                 set but the hook never installed (PySocks missing in
                                 THIS interpreter), RAISE — a direct socket would leak.
      - no proxy / no_proxy   -> return None; the caller connects directly (fine).
    """
    proxy = (os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
             or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
             or os.environ.get("ALL_PROXY") or os.environ.get("all_proxy"))
    if not proxy:
        return None
    if urlsplit(proxy).scheme.startswith("socks"):
        if os.environ.get("CTI_PROXY_SOCKS_ACTIVE") == "1":
            return None
        raise OSError("SOCKS proxy configured but the PySocks socket hook is not "
                      "active in this interpreter — refusing to dial the target "
                      "directly (install pysocks, e.g. into $INTEL_PY)")
    if _host_bypassed((host or "").lower(), no_proxy_hosts()):
        return None
    p = urlsplit(proxy)
    sock = socket.create_connection((p.hostname, p.port), timeout=timeout)
    try:
        line = (f"CONNECT {host}:{port} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n")
        if p.username:
            tok = base64.b64encode(
                f"{p.username}:{p.password or ''}".encode()).decode()
            line += f"Proxy-Authorization: Basic {tok}\r\n"
        sock.sendall((line + "\r\n").encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
        status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
        if " 200 " not in status:
            raise OSError(f"proxy CONNECT refused: {status.strip() or 'no response'}")
        return sock
    except Exception:
        try:
            sock.close()
        except OSError:
            pass
        raise


# ───────────────────────────────────────────────────────── the public hook
def install(cfg=None):
    """Install the process-global proxy egress. Safe to call from any script's
    startup — no-ops when disabled or no proxy is configured. Returns the URL of
    the proxy this process starts on, or None."""
    global _INSTALLED
    if _INSTALLED:
        return os.environ.get("HTTPS_PROXY") or None
    load_env_file()
    cfg = cfg or load_store()
    if not is_enabled(cfg):
        return None
    pool = build_pool(cfg)
    if not pool:
        return None
    start = pick_start(pool, rotation_mode(cfg))
    chosen = pool[start]
    _INSTALLED = True
    npx = no_proxy_hosts(cfg)
    if npx:
        os.environ["NO_PROXY"] = os.environ["no_proxy"] = ",".join(npx)
    if urlsplit(chosen).scheme.startswith("socks"):
        # SOCKS routes raw sockets only through the in-process PySocks hook.
        os.environ["ALL_PROXY"] = os.environ["all_proxy"] = chosen  # for requests[socks]
        ok = _install_socks(chosen)
        os.environ["CTI_PROXY_SOCKS_ACTIVE"] = "1" if ok else "0"
        if ok:
            # Hook live: let urllib use the hooked plain socket. A socks URL left in
            # HTTP(S)_PROXY would make urllib mis-handle it as an HTTP proxy.
            for _v in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
                os.environ.pop(_v, None)
        else:
            # No hook (PySocks missing here): force urllib to FAIL CLOSED (it errors
            # on a socks value used as an HTTP proxy) rather than dialling direct.
            os.environ["HTTP_PROXY"] = os.environ["http_proxy"] = chosen
            os.environ["HTTPS_PROXY"] = os.environ["https_proxy"] = chosen
            print("[cti_proxy] SOCKS pool configured but PySocks is not active in "
                  "this interpreter — HTTP and raw probes fail closed; install "
                  "pysocks here (e.g. into $INTEL_PY).", file=sys.stderr)
        return chosen
    # HTTP/HTTPS proxy: urllib via the FailoverOpener + env for child processes.
    os.environ["HTTP_PROXY"] = os.environ["http_proxy"] = chosen
    os.environ["HTTPS_PROXY"] = os.environ["https_proxy"] = chosen
    os.environ["ALL_PROXY"] = os.environ["all_proxy"] = chosen
    os.environ.pop("CTI_PROXY_SOCKS_ACTIVE", None)
    urllib.request.install_opener(
        FailoverOpener(pool, start, allow_direct(cfg), npx))
    return chosen


def test_proxy(proxy, url=None, timeout=15):
    """Probe one proxy against an IP-echo endpoint. Returns (ok, detail)."""
    url = url or DEFAULT_TEST_URL
    try:
        if proxy and urlsplit(proxy).scheme.startswith("socks"):
            return None, "SOCKS test needs PySocks + a live socket monkeypatch"
        ph = (urllib.request.ProxyHandler({"http": proxy, "https": proxy})
              if proxy else urllib.request.ProxyHandler({}))
        opener = urllib.request.build_opener(ph)
        req = urllib.request.Request(url, headers={"User-Agent": "cti-expert-proxy/1.0"})
        with opener.open(req, timeout=timeout) as r:
            body = r.read(400).decode("utf-8", "replace").strip()
        return True, body
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ───────────────────────────────────────────────────────── tiny self-CLI
def _main(argv):
    cmd = argv[0] if argv else "status"
    cfg = load_store()
    pool = build_pool(cfg)
    if cmd == "status":
        print(f"enabled     : {is_enabled(cfg)}")
        print(f"rotation    : {rotation_mode(cfg)}")
        print(f"allow_direct: {allow_direct(cfg)}")
        print(f"pool ({len(pool)}):")
        for i, p in enumerate(pool):
            print(f"  [{i}] {p}")
        print(f"store       : {STORE_PATH}")
        return 0
    if cmd == "pick":
        if not pool:
            print("(no proxies configured)")
            return 1
        print(pool[pick_start(pool, rotation_mode(cfg))])
        return 0
    if cmd == "test":
        url = argv[1] if len(argv) > 1 else None
        rc = 0
        for p in pool or [None]:
            ok, detail = test_proxy(p, url)
            print(f"{'OK ' if ok else 'ERR'} {p or '(direct)'} -> {detail}")
            rc = rc or (0 if ok else 2)
        return rc
    print(f"unknown command: {cmd} (use status|pick|test)", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
