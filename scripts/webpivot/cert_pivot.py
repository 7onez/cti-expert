#!/usr/bin/env python3
# cti-expert skill — ported/adapted from the Quarry OSINT toolkit
# (github.com/7onez/quarry): cert_pivot_runner.py.
"""cert_pivot.py — pivot on a TLS certificate to find OTHER hosts that serve the SAME
cert. Distinct from /cert-history (which times-lines a domain's own certs): a shared
leaf-cert fingerprint is a strong same-operator signal, and a cert's SAN list often
names sibling domains outright.

Keyless (default), all via stdlib:
  * live-fetches the leaf cert of a domain and computes its SHA-1 / SHA-256 fingerprint
  * reads the domain's CT history through the shared wp_ct client (crt.sh → PostgreSQL →
    keyless backups, per-source status) + extracts SAN sibling hostnames
  * emits copy-paste pivot queries + clickable deep-links for crt.sh / Shodan / Censys / FOFA

Premium (auto-fires only when keys are set, strictly additive):
  * SHODAN_API_KEY               → ssl.cert.fingerprint pivot → hosts
  * CENSYS_API_KEY (+ CENSYS_ORG_ID) → Censys Platform cert.fingerprint_sha256 search → hosts

Usage:
  uv run cert_pivot.py suspicious-site.top --pretty
  uv run cert_pivot.py suspicious-site.top -o <case>/raw/cert.suspicious-site.top.json
  uv run cert_pivot.py --sha256 <hex> --sha1 <hex>     # pivot an explicit fingerprint
  uv run cert_pivot.py suspicious-site.top --no-live    # crt.sh + link-build only

Never raises on network/parse errors — every failure degrades to an "error" note.
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
import sys
import os
import ssl
import time
import json
import socket
import re
import hashlib
import base64
import argparse
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

# --- egress proxy / rotation: route outbound HTTP through the /proxy pool ----
def _install_cti_proxy():
    import os as _o, sys as _s
    _b = _o.path.dirname(_o.path.abspath(__file__))
    for _ in range(6):
        _c = _o.path.join(_b, "proxy", "cti_proxy.py")
        if _o.path.isfile(_c):
            _s.path.insert(0, _o.path.dirname(_c))
            try:
                import cti_proxy
                cti_proxy.install()
            except Exception:
                pass
            return
        _p = _o.path.dirname(_b)
        if _p == _b:
            return
        _b = _p
_install_cti_proxy()

_UA = "cti-expert/1.0 (+cert-pivot)"

# --------------------------------------------------------------- shared key store
_CUSTOMIZATION_ENV = (os.environ.get("CTI_API_KEYS_ENV")
                      or os.environ.get("CTI_WEBPIVOT_ENV")
                      or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      "..", "..", ".env"))


def _load_customization_env(path=_CUSTOMIZATION_ENV):
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k and k not in os.environ:
                    os.environ[k] = v
    except Exception:
        pass


_load_customization_env()


def _secret(*names):
    for n in names:
        v = os.environ.get(n)
        if v and v.strip():
            return v.strip()
    return None


def _ceiling():
    """Per-call ceiling via cti_timeouts (env CTI_CALL_TIMEOUT → skill-root .env →
    references/timeouts.json → 5000), so a standalone run still honours the analyst's setting."""
    import os as _o, sys as _s
    _s.path.insert(0, _o.path.dirname(_o.path.dirname(_o.path.abspath(__file__))))  # -> scripts/
    try:
        from cti_timeouts import CALL_TIMEOUT
        return int(CALL_TIMEOUT)
    except Exception:
        try:
            v = int(_o.environ.get("CTI_CALL_TIMEOUT") or 0)
        except ValueError:
            v = 0
        return v if v > 0 else 5000


_CALL_TIMEOUT = _ceiling()


def _get(url, timeout=_CALL_TIMEOUT, headers=None, retries=4, backoff=3):
    """GET → (text, error). Never raises.

    `timeout` is a TOTAL wall-clock budget across ALL retries + backoff (not per
    attempt), so the resolved per-call ceiling holds even though crt.sh is frequently overloaded
    and retried. Transient failures (429/5xx, timeouts, resets, empty bodies) retry;
    non-retryable 4xx bail early.
    """
    last = None
    deadline = time.monotonic() + timeout
    for attempt in range(retries):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            req = Request(url, headers={"User-Agent": _UA, **(headers or {})})
            with urlopen(req, timeout=remaining) as r:
                text = r.read().decode("utf-8", "replace")
            if not text.strip():
                raise ValueError("empty response")  # overloaded — worth retrying
            return text, None
        except HTTPError as e:  # noqa: BLE001
            last = f"HTTPError: {e.code} {e.reason}"
            if e.code not in (429, 500, 502, 503, 504):
                return None, last  # 4xx (other than 429) won't recover on retry
        except Exception as e:  # noqa: BLE001
            last = f"{type(e).__name__}: {e}"
        if attempt < retries - 1:
            nap = min(backoff * (attempt + 1), max(0.0, deadline - time.monotonic()))
            if nap <= 0:
                break
            time.sleep(nap)
    return None, last or "request failed"


# ------------------------------------------------------------------ egress (one rail)
def _proxy_layer():
    try:
        import cti_proxy
        return cti_proxy
    except Exception:  # noqa: BLE001
        return None


def _egress_socket(host, port, timeout):
    """The ONLY way this script dials a target or hit IP. Through cti_proxy.proxied_connection: an
    HTTP proxy tunnels (refused tunnel RAISES), a SOCKS pool needs its hook, `None` means the proxy
    layer judged direct safe. Without the proxy layer we refuse — never a silent direct leak."""
    cp = _proxy_layer()
    if cp is None:
        raise OSError("proxy layer (cti_proxy) unavailable — refusing a direct connection")
    sock = cp.proxied_connection(host, port, timeout)
    return sock or socket.create_connection((host, port), timeout=timeout)


def _configured_proxy():
    for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        if os.environ.get(k):
            return os.environ[k]
    return None


def _harness_module(name):
    """intel_engine/harness/<name> (audit, case_scope — both stdlib-only), or None."""
    hdir = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "..", "..", "intel_engine", "harness"))
    if hdir not in sys.path:
        sys.path.append(hdir)                      # append: never shadow WebPivot modules
    try:
        return __import__(name)
    except Exception:  # noqa: BLE001
        return None


def _case_id():
    d = os.environ.get("WP_CASE_DIR")
    return os.environ.get("INTEL_CASE") or (os.path.basename(os.path.normpath(d)) if d else None)


def _case_hostile(case):
    """The case's intake posture (cases/<case>/scope.json → case_scope.is_hostile); None when no
    case is in scope, so audit falls back to HARNESS_HOSTILE. A scope that cannot be read is
    treated as hostile — guessing 'safe to touch' is the expensive mistake."""
    if not case:
        return None
    cs = _harness_module("case_scope")
    if cs is None:
        return True
    scope = cs.load(case)
    return None if scope is None else (cs.is_hostile(scope) or None)


def egress_gate(domain, passive=False):
    """(allowed, reason) for ANY live contact this run makes — the target's leaf certificate, its
    page, and the Host-header probe of each hit IP. Decided ONCE, before the first byte:
      passive                        → not run
      no proxy layer                 → not run (never a direct fallback)
      audit.gate('cert_pivot', …)    → the same egress policy every outbound tool obeys: a
                                       HOSTILE case / HARNESS_HOSTILE without a proxy is denied
                                       (and ledgered); a configured proxy makes it allowed
      gate unavailable               → allowed only through a configured proxy."""
    if passive:
        return False, "passive posture (--passive / --no-live): live contact not run"
    if _proxy_layer() is None:
        return False, "proxy layer (cti_proxy) unavailable: live contact not run (no direct fallback)"
    proxy = _configured_proxy()
    audit = _harness_module("audit")
    if audit is None:
        return ((True, "") if proxy else
                (False, "egress gate unavailable and no proxy configured: live contact not run"))
    case = _case_id()
    ok, why = audit.gate("cert_pivot", {"domain": domain, "stage": "live-contact",
                                        "proxy": bool(proxy)},
                         case=case, hostile=_case_hostile(case))
    return ok, why


# ---------------------------------------------------------------- live cert fetch
def fetch_leaf_fingerprints(host, port=443, timeout=15):
    """Return {'sha1','sha256','sans','issuer'} of the served leaf cert, or {'error':...}.

    Dials through _egress_socket only. A validating handshake yields the parsed SANs + issuer; a
    cert that does not validate (hostile/expired/self-signed infra still serves one worth
    fingerprinting) is re-read unverified for the DER — fingerprints + DER-scanned SANs, no issuer.
    """
    def _handshake(ctx):
        sock = _egress_socket(host, port, timeout)
        with sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                return ss.getpeercert(binary_form=True), ss.getpeercert()

    try:
        try:
            der, parsed = _handshake(ssl.create_default_context())
        except ssl.SSLCertVerificationError:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            der, parsed = _handshake(ctx)
    except Exception as e:  # noqa: BLE001 — tunnel refused / no proxy layer: do NOT leak
        return {"error": f"egress refused or failed: {type(e).__name__}: {e}"}
    if not der:
        return {"error": "no certificate presented"}
    out = {"sha1": hashlib.sha1(der).hexdigest(), "sha256": hashlib.sha256(der).hexdigest(),
           "serial": _der_serial(der)}
    if parsed:
        out["sans"] = [v.lower() for t, v in parsed.get("subjectAltName", ()) if t.lower() == "dns"]
        iss = {k: v for rdn in parsed.get("issuer") or () for k, v in rdn}
        out["issuer"] = iss.get("organizationName") or iss.get("commonName")
    else:
        rec = _engine_module("wp_recon")
        out["sans"] = list(rec._der_sans(der)) if rec and hasattr(rec, "_der_sans") else []
        out["issuer"] = None
    return out


# ------------------------------------------------------------- engine modules
def _engine_module(name):
    """A canonical engine module from intel_engine/WebPivot/tools (wp_ct, wp_censys), or None."""
    tools = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                          "..", "..", "intel_engine", "WebPivot", "tools"))
    if tools not in sys.path:
        sys.path.insert(0, tools)
    try:
        return __import__(name)
    except Exception:  # noqa: BLE001
        return None


# ------------------------------------------------------------- FOFA cert serial
# FOFA answers NOTHING for `cert="<sha256>"` (Quarry, live-verified 2026-10); the working cert
# pivot is `cert.sn="<decimal x509 serial>"`. Only some CT sources store the REAL serial — the rest
# store a hash or an issuance id that cert.sn can never match. The allow-list lives in
# WebPivot/references/ct_sources.json → real_serial_sources; the fallback is crt.sh alone.
_CT_SERIAL_FALLBACK = {"real_serial_sources": ["crt.sh"]}


def _real_serial_sources():
    refs = _engine_module("wp_refs")
    if refs is None:
        return frozenset(_CT_SERIAL_FALLBACK["real_serial_sources"])
    doc = refs.load_ref(refs.ref_path(refs.__file__, "ct_sources.json"), _CT_SERIAL_FALLBACK)
    return frozenset(doc["real_serial_sources"])


REAL_SERIAL_SOURCES = _real_serial_sources()
# The target controls every certificate field it presents; a quote/backslash/control char could
# close the FOFA string and append terms (`x" || ip="…`), so such a value is never queried.
_QUERY_UNSAFE = re.compile(r'["\\\x00-\x1f\x7f]')


def _der_serial(der):
    """The x509 serialNumber of a DER certificate as lowercase hex ('' if unparsable). The served
    leaf is the one certificate whose serial is never a CT-index surrogate."""
    def tlv(i):
        tag, ln = der[i], der[i + 1]
        i += 2
        if ln & 0x80:
            n = ln & 0x7F
            ln = int.from_bytes(der[i:i + n], "big")
            i += n
        return tag, ln, i
    try:
        tag, _, i = tlv(0)                       # Certificate SEQUENCE
        if tag != 0x30:
            return ""
        tag, _, i = tlv(i)                       # tbsCertificate SEQUENCE
        if tag != 0x30:
            return ""
        tag, ln, j = tlv(i)
        if tag == 0xA0:                          # [0] version (absent on v1 certs)
            tag, ln, j = tlv(j + ln)
        return der[j:j + ln].hex() if tag == 0x02 and ln else ""
    except (IndexError, TypeError):
        return ""


def fofa_serial(serial):
    """A hex x509 serial (colons allowed) → the DECIMAL string FOFA's cert.sn expects, or '' when
    the value is empty, unsafe to embed, not hex, or longer than 20 bytes (crt.sh may prefix a
    00 sign byte, stripped with the other leading zeros)."""
    s = str(serial or "")
    if not s or _QUERY_UNSAFE.search(s):
        return ""
    h = s.strip().lower().replace(":", "").lstrip("0")
    if not h or len(h) > 40 or not re.fullmatch(r"[0-9a-f]+", h):
        return ""
    return str(int(h, 16))


def ct_real_serial(cert):
    """Decimal serial of a CT record for FOFA, or '' when no source behind it stores the real x509
    serial (CertIndex/CertSpotter/Censys/Shodan CTL surrogates) — never a known-dead query."""
    if not REAL_SERIAL_SOURCES.intersection(cert.get("sources") or ()):
        return ""
    return fofa_serial(cert.get("serial_number"))


def fofa_cert_query(serial_dec):
    """FOFA's cert pivot for a decimal serial from fofa_serial()/ct_real_serial(), or None."""
    return f'cert.sn="{serial_dec}"' if serial_dec and str(serial_dec).isdigit() else None


# ------------------------------------------------------------------------ CT history
def crtsh_history(domain, cap=40):
    """CT history through the shared client (wp_ct: crt.sh → PostgreSQL → keyless backups) →
    newest `cap` certs, every SAN sibling hostname, and the per-source status + completeness line.
    A capped listing records cert_total + truncated; an outage is an error, never "no certs"."""
    ct = _engine_module("wp_ct")
    if ct is None:
        return {"certs": [], "san_siblings": [], "error": "wp_ct unavailable (intel_engine not found)"}
    r = ct.ct_search(domain, max_certs=cap, max_subdomains=None)
    certs = [{
        "crtsh_id": c.get("crtsh_id") or "",
        "serial_number": c.get("serial") or "",
        "sha256": c.get("sha256") or "",
        "not_before": c.get("not_before") or "",
        "not_after": c.get("not_after") or "",
        "issuer": (c.get("issuer") or "")[:120],
        "sources": c.get("sources") or [],
        "confidence": c.get("confidence"),
    } for c in r.get("certs") or []]
    tgt = domain.lower().lstrip("*.")
    siblings = sorted(n for n in r.get("subdomains") or []
                      if n != tgt and "." in n and not n.endswith(".arpa"))
    out = {"certs": certs, "san_siblings": siblings, "cert_total": r.get("cert_total", 0),
           "truncated": bool(r.get("truncated")), "ct_status": r.get("ct_status") or {},
           "completeness": r.get("completeness"), "completeness_line": r.get("completeness_line")}
    if r.get("error"):
        out["error"] = r["error"]
    return out


# ---------------------------------------------------- passive links + engine queries
def _wp_censys():
    """The canonical Censys Platform client (intel_engine/WebPivot/tools/wp_censys.py), or None."""
    return _engine_module("wp_censys")


def _censys_cenql(sha256):
    """Hosts SERVING the cert: the `web.` (hostname:port) and `host.` (IP) templates, OR'd into one
    search. The `cert.` template matches the certificate record itself, which carries no IP/host."""
    cen = _wp_censys()
    q = [t for t in (cen.cenql_for("tls_cert:fingerprint_sha256", sha256) if cen else [])
         if t.startswith(("web.", "host."))]
    q = q or [f"web.cert.fingerprint_sha256={sha256}", f"host.services.cert.fingerprint_sha256={sha256}"]
    return " or ".join(q)


def build_queries(sha1, sha256, serial_dec=""):
    q = {}
    if sha256:
        # Shodan's ssl.cert.fingerprint matches the SHA-256 fingerprint on modern data.
        q["shodan"] = f"ssl.cert.fingerprint:{sha256}"
        q["censys"] = _censys_cenql(sha256)
    fofa = fofa_cert_query(serial_dec)
    if fofa:
        q["fofa"] = fofa
    if sha1:
        q["shodan_sha1"] = f"ssl.cert.fingerprint:{sha1}"
    return q


def passive_links(domain, sha1, sha256, crtsh_id="", serial="", serial_dec=""):
    links = []
    if crtsh_id:
        links.append({"engine": "crt.sh", "label": f"crt.sh entry #{crtsh_id}",
                      "url": f"https://crt.sh/?id={crtsh_id}"})
    elif serial:
        links.append({"engine": "crt.sh", "label": "crt.sh by serial",
                      "url": f"https://crt.sh/?serial={serial}"})
    elif domain:
        links.append({"engine": "crt.sh", "label": "crt.sh by domain",
                      "url": f"https://crt.sh/?q={quote(domain)}"})
    if sha256:
        links.append({"engine": "shodan_web", "label": "Shodan cert fingerprint (SHA-256)",
                      "url": f"https://www.shodan.io/search?query=ssl.cert.fingerprint%3A{sha256}"})
        cen = _wp_censys()
        cenql = _censys_cenql(sha256)
        links.append({"engine": "censys_web", "label": "Censys cert fingerprint (SHA-256)",
                      "url": (cen.censys_ui_url(cenql) if cen
                              else "https://platform.censys.io/search?q=" + quote(cenql, safe=""))})
    fofa = fofa_cert_query(serial_dec)
    if fofa:
        fofa_b64 = base64.b64encode(fofa.encode()).decode()
        links.append({"engine": "fofa_web", "label": "FOFA cert serial search",
                      "url": f"https://en.fofa.info/result?qbase64={fofa_b64}&full=true"})
    if sha1:
        links.append({"engine": "shodan_web", "label": "Shodan cert fingerprint (SHA-1 alt)",
                      "url": f"https://www.shodan.io/search?query=ssl.cert.fingerprint%3A{sha1}"})
    return links


# ------------------------------------------------------------ active pivots (keyed)
def shodan_pivot(sha256, sha1, cap=20):
    key = _secret("SHODAN_API_KEY")
    if not key:
        return [], "no SHODAN_API_KEY (skipped)"
    hits = []
    for fp in [f for f in (sha256, sha1) if f]:
        url = (f"https://api.shodan.io/shodan/host/search?key={key}"
               f"&query=ssl.cert.fingerprint:{fp}")
        text, err = _get(url, timeout=_CALL_TIMEOUT)
        if err or not text:
            continue
        try:
            data = json.loads(text)
        except Exception:
            continue
        for m in (data.get("matches") or [])[:cap]:
            ip = m.get("ip_str", "")
            hits.append({"engine": "shodan", "query": f"ssl.cert.fingerprint:{fp}",
                         "matched_ip": ip, "matched_host": (m.get("hostnames") or [""])[0],
                         "scan_date": str(m.get("timestamp") or "")[:10] or None,
                         "url": f"https://www.shodan.io/host/{ip}" if ip else ""})
        if hits:
            break  # sha256 succeeded; don't double-count with sha1
    return hits, (None if hits else "no results / auth failure")


def censys_pivot(sha256, cap=20):
    """Censys Platform search (PAT bearer + X-Organization-ID) via the canonical wp_censys client,
    which owns the spend guard, the credit ledger and the Free-plan 403 -> UI-link degradation."""
    if not sha256:
        return [], None
    cen = _wp_censys()
    if cen is None:
        return [], "wp_censys unavailable (intel_engine not found) (skipped)"
    if not cen.censys_configured():
        return [], "no CENSYS_API_KEY / CENSYS_PAT (skipped)"
    q = _censys_cenql(sha256)
    res = cen.censys_search(q, page_size=max(1, min(100, cap)))
    if not res or res.get("skipped") or res.get("error"):
        res = res or {}
        why = res.get("skipped") or res.get("error") or "no response"
        return [], f"{why}" + (f" — run by hand: {res['ui_url']}" if res.get("ui_url") else "")
    hits = []
    for h in (res.get("hits") or [])[:cap]:
        ip = h.get("ip") or ""
        host = h.get("hostname") or ""
        if not (ip or host):
            continue                     # e.g. a certificate record: names, but no serving host
        hits.append({"engine": "censys", "query": q, "matched_ip": ip, "matched_host": host,
                     "url": (cen.censys_ui_url((cen.cenql_for("ip", ip) or [f"host.ip={ip}"])[0]) if ip
                             else cen.censys_ui_url(f'web.hostname="{host}"') if host else "")})
    return hits, (None if hits else "no results")


# ---------------------------------------------------------- origin check (1): Host-header probe
def _https_body(connect_host, sni_host, timeout, max_bytes=524288):
    """GET / from `connect_host`:443 with SNI + `Host:` = `sni_host`, through the same egress policy
    as the leaf fetch (cti_proxy tunnel when configured, never a silent direct leak). → (status,
    sha256 of the body) or raises."""
    import http.client
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _sock():
        return _egress_socket(connect_host, 443, timeout)

    class _Conn(http.client.HTTPSConnection):
        def connect(self):
            self.sock = ctx.wrap_socket(_sock(), server_hostname=sni_host)

    conn = _Conn(connect_host, 443, timeout=timeout, context=ctx)
    try:
        conn.request("GET", "/", headers={"Host": sni_host, "User-Agent": _UA, "Accept": "*/*"})
        resp = conn.getresponse()
        return resp.status, hashlib.sha256(resp.read(max_bytes)).hexdigest()
    finally:
        conn.close()


def origin_probe(target, ips, max_ips=10, timeout=15):
    """Origin check (1): does each hit IP serve the TARGET's content for `Host: <target>`? Compares
    the body hash with the target's own answer. Active, so it runs only with live collection; every
    failure is recorded as such, never as a match. → {ip: {ran, match, status, error}}"""
    out = {}
    try:
        base_status, base_hash = _https_body(target, target, timeout)
    except Exception as e:  # noqa: BLE001
        return {ip: {"ran": False, "match": False, "error": f"target baseline: {type(e).__name__}"}
                for ip in ips[:max_ips]}
    for ip in ips[:max_ips]:
        try:
            st, h = _https_body(ip, target, timeout)
            out[ip] = {"ran": True, "match": h == base_hash and st == base_status, "status": st}
        except Exception as e:  # noqa: BLE001 — unreachable is UNKNOWN (check not run), never a "no"
            out[ip] = {"ran": False, "match": False, "error": f"{type(e).__name__}: {e}"[:120]}
    return out


def grade_hits(domain, sha256, hits, leaf=None, probe=None):
    """Active-pivot hits → graded "Related hosts (unverified)" rows (shared contract: wp_related).
    Check (2) passes only when `leaf` (the target's live certificate) IS the pivoted one, is not
    CDN-managed and names the target; (3) history needs a case and is `not run` here."""
    wr = _engine_module("wp_related")
    if wr is None or not domain:
        return []
    leaf = leaf or {}
    leaf_sha = str(leaf.get("fingerprint_sha256") or "").lower()
    leaf_ok = (bool(sha256) and leaf_sha == sha256.lower()
               and not wr._cdn_cert(leaf.get("issuer"))
               and any(wr._san_covers(n, domain.lower()) for n in leaf.get("sans") or []))
    rows, seen = [], {}
    for h in hits:
        ip, host = h.get("matched_ip") or None, (h.get("matched_host") or "").lower() or None
        if host == domain.lower():
            continue
        key = (host, ip)
        if key in seen:
            seen[key]["engines"] = sorted(set(seen[key]["engines"]) | {h["engine"]})
            continue
        checks = {c: "n/a" for c in wr.CHECKS}
        if ip:
            pr = (probe or {}).get(ip) or {}
            checks["host_header"] = "pass" if pr.get("match") else "fail" if pr.get("ran") else "not run"
            checks["cert_san"] = "pass" if leaf_ok else ("fail" if leaf else "not run")
            checks["history"] = "not run"
            cls = wr._classify(ip)
            checks["non_cdn"] = "pass" if cls == "origin" else "fail" if cls else "not run"
        passed, rung = wr.grade(checks)
        seen[key] = {"host": host, "ip": ip, "target": domain.lower(), "engines": [h["engine"]],
                     "shared_kind": "tls_cert:fingerprint_sha256", "shared_value": sha256,
                     "scan_date": h.get("scan_date"), "checks": checks, "passed": passed, "rung": rung}
        rows.append(seen[key])
    rows.sort(key=lambda r: (-len(r["passed"]), r["host"] or "", r["ip"] or ""))
    return rows


# --------------------------------------------------------------------------- driver
def run(domain=None, sha1="", sha256="", live=True, use_crtsh=True, cap=20, passive=False,
        x509_serial=""):
    result = {"target": domain, "fingerprints": {}, "crtsh": {},
              "passive_links": [], "queries": {}, "active_pivots": [],
              "new_hosts": [], "notes": [], "summary": {}}

    # ONE egress decision before the first byte to the target or any hit IP (leaf certificate,
    # page baseline, Host-header probe). Denied or passive → every live check reads `not run`.
    leaf, fofa_sn, sn_from = {}, "", ""
    if x509_serial:
        fofa_sn = fofa_serial(x509_serial)
        sn_from = "explicit" if fofa_sn else ""
        if not fofa_sn:
            result["notes"].append("--serial rejected: not a hex x509 serial (or unsafe to embed)")
    if domain:
        ok, why = egress_gate(domain, passive=passive or not live)
        result["egress"] = {"allowed": ok, "reason": why or None}
        if not ok:
            live = False
            result["notes"].append(f"live contact not run: {why}")
    if domain and live:
        fp = fetch_leaf_fingerprints(domain)
        if "error" in fp:
            result["notes"].append(f"live cert fetch: {fp['error']}")
        else:
            leaf = {"fingerprint_sha256": fp["sha256"], "issuer": fp.get("issuer"),
                    "sans": fp.get("sans") or []}
            if not (sha1 or sha256):
                sha1, sha256 = fp["sha1"], fp["sha256"]
            if not fofa_sn and sha256 == fp["sha256"]:
                fofa_sn = fofa_serial(fp.get("serial"))
                sn_from = "live leaf" if fofa_sn else ""
    result["fingerprints"] = {"sha1": sha1, "sha256": sha256}

    crtsh_id = serial = ""
    if domain and use_crtsh:
        ch = crtsh_history(domain)
        result["crtsh"] = ch
        if ch.get("error"):
            result["notes"].append(f"CT: {ch['error']}")
        elif ch.get("completeness") not in (None, "full"):
            result["notes"].append(f"CT: {ch['completeness_line']}")
        if ch.get("certs"):
            crtsh_id = ch["certs"][0].get("crtsh_id", "")
            serial = ch["certs"][0].get("serial_number", "")
        if not fofa_sn:
            # The pivoted fingerprint's own CT record first, else the newest cert with a real serial.
            certs = sorted(ch.get("certs") or [], key=lambda c: not (sha256 and c.get("sha256") == sha256))
            for c in certs:
                fofa_sn = ct_real_serial(c)
                if fofa_sn:
                    sn_from = "CT (" + ", ".join(c.get("sources") or []) + ")"
                    break
        result["new_hosts"].extend(ch.get("san_siblings", []))

    result["fingerprints"].update({"serial_decimal": fofa_sn, "serial_source": sn_from or None})
    if not fofa_sn:
        result["notes"].append("FOFA cert pivot not emitted: no real x509 serial (FOFA cert=<fingerprint> "
                               "matches nothing; CT-index surrogate serials are skipped)")
    result["queries"] = build_queries(sha1, sha256, fofa_sn)
    result["passive_links"] = passive_links(domain or "", sha1, sha256, crtsh_id, serial, fofa_sn)

    sh_hits, sh_note = shodan_pivot(sha256, sha1, cap=cap)
    cn_hits, cn_note = censys_pivot(sha256, cap=cap)
    result["active_pivots"] = sh_hits + cn_hits
    for note in (sh_note, cn_note):
        if note:
            result["notes"].append(note)
    for h in result["active_pivots"]:
        for v in (h.get("matched_ip"), h.get("matched_host")):
            if v and v not in result["new_hosts"]:
                result["new_hosts"].append(v)

    # Every hit is a RELATED host until origin checks agree — never the target's hosting or origin.
    # Check (1) is an active Host-header request: only when the egress gate allowed live contact.
    probe = {}
    if domain and result["active_pivots"]:
        if live:
            wr = _engine_module("wp_related")
            ips = sorted({h["matched_ip"] for h in result["active_pivots"] if h.get("matched_ip")})
            cfg = wr.CFG if wr else {"probe_max_ips": 10, "probe_timeout_seconds": 15}
            probe = origin_probe(domain, ips, max_ips=int(cfg["probe_max_ips"]),
                                 timeout=int(cfg["probe_timeout_seconds"]))
        result["origin_probe"] = probe
        result["related_hosts"] = grade_hits(domain, sha256, result["active_pivots"], leaf, probe)

    result["new_hosts"] = sorted(set(result["new_hosts"]))
    result["summary"] = {
        "have_fingerprint": bool(sha1 or sha256),
        "san_siblings": len(result.get("crtsh", {}).get("san_siblings", [])),
        "active_hits": len(result["active_pivots"]),
        "new_hosts": len(result["new_hosts"]),
    }
    return result


def main():
    ap = argparse.ArgumentParser(
        description="Pivot on a TLS cert fingerprint to find other hosts serving it.")
    ap.add_argument("domain", nargs="?", help="domain to fetch + pivot (e.g. site.top)")
    ap.add_argument("--sha1", default="", help="pivot an explicit SHA-1 fingerprint (hex)")
    ap.add_argument("--sha256", default="", help="pivot an explicit SHA-256 fingerprint (hex)")
    ap.add_argument("--serial", default="",
                    help="explicit x509 serial (hex) for the FOFA cert.sn pivot")
    ap.add_argument("--no-live", action="store_true",
                    help="no live contact with the target or hit IPs (same as --passive)")
    ap.add_argument("--passive", action="store_true",
                    help="passive posture: CT + third-party indexes only; live checks read `not run`")
    ap.add_argument("--proxy", default="",
                    help="route every live contact (leaf cert, page, Host-header probe) via this proxy")
    ap.add_argument("--no-crtsh", action="store_true", help="skip crt.sh history + SAN pivot")
    ap.add_argument("--cap", type=int, default=20, help="max results per active pivot query")
    ap.add_argument("--pretty", action="store_true", help="pretty-print JSON")
    ap.add_argument("-o", "--out", help="write JSON to file")
    args = ap.parse_args()

    if not args.domain and not (args.sha1 or args.sha256 or args.serial):
        ap.error("provide a domain, or --sha1/--sha256/--serial")

    if args.proxy:
        os.environ["HTTPS_PROXY"] = args.proxy        # read by cti_proxy.proxied_connection
    result = run(domain=args.domain, sha1=args.sha1.lower(), sha256=args.sha256.lower(),
                 live=not args.no_live, use_crtsh=not args.no_crtsh, cap=args.cap,
                 passive=args.passive, x509_serial=args.serial)

    s = result["summary"]
    print(f"cert_pivot: fingerprint={'yes' if s['have_fingerprint'] else 'no'}; "
          f"{s['san_siblings']} SAN sibling(s); {s['active_hits']} active hit(s); "
          f"{s['new_hosts']} new host(s)", file=sys.stderr)

    text = json.dumps(result, ensure_ascii=False, indent=2 if args.pretty else None)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
