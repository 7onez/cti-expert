#!/usr/bin/env python3
# cti-expert skill — ported/adapted from the Quarry OSINT toolkit
# (github.com/7onez/quarry): cert_pivot_runner.py.
"""cert_pivot.py — pivot on a TLS certificate to find OTHER hosts that serve the SAME
cert. Distinct from /cert-history (which times-lines a domain's own certs): a shared
leaf-cert fingerprint is a strong same-operator signal, and a cert's SAN list often
names sibling domains outright.

Keyless (default), all via stdlib:
  * live-fetches the leaf cert of a domain and computes its SHA-1 / SHA-256 fingerprint
  * queries crt.sh (JSON) for the cert history + extracts SAN sibling hostnames
  * emits copy-paste pivot queries + clickable deep-links for crt.sh / Shodan / Censys / FOFA

Premium (auto-fires only when keys are set, strictly additive):
  * SHODAN_API_KEY               → ssl.cert.fingerprint pivot → hosts
  * CENSYS_API_ID + _API_SECRET  → leaf_data.fingerprint_sha256 pivot → hosts

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


def _get(url, timeout=1800, headers=None, retries=4, backoff=3):
    """GET → (text, error). Never raises.

    `timeout` is a TOTAL wall-clock budget across ALL retries + backoff (not per
    attempt), so the 30-min ceiling holds even though crt.sh is frequently overloaded
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


# ---------------------------------------------------------------- live cert fetch
def fetch_leaf_fingerprints(host, port=443, timeout=15):
    """Return {'sha1','sha256'} of the served leaf cert (DER), or {'error':...}.

    verify_mode is disabled on purpose — hostile/expired/self-signed infra still
    serves a cert worth fingerprinting.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        # Respect a configured proxy — a raw socket here would leak the real IP to
        # the target. proxied_connection tunnels via CONNECT (HTTP proxy) or returns
        # None when going direct is safe (no proxy, or SOCKS already hooks sockets).
        sock = None
        _cp = None
        try:
            import cti_proxy as _cp
        except Exception:
            _cp = None              # proxy layer absent -> connect directly, as before
        if _cp is not None:
            try:
                sock = _cp.proxied_connection(host, port, timeout)
            except Exception as e:  # proxy configured but tunnel failed -> do NOT leak
                return {"error": f"proxy tunnel failed: {type(e).__name__}: {e}"}
        if sock is None:
            sock = socket.create_connection((host, port), timeout=timeout)
        with sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
        if not der:
            return {"error": "no certificate presented"}
        return {
            "sha1": hashlib.sha1(der).hexdigest(),
            "sha256": hashlib.sha256(der).hexdigest(),
        }
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"}


# ------------------------------------------------------------------------ crt.sh
def crtsh_history(domain, timeout=1800, cap=40):
    """crt.sh JSON → recent certs (id/serial/validity/issuer) + SAN sibling hostnames."""
    url = f"https://crt.sh/?q={quote(domain)}&output=json"
    text, err = _get(url, timeout=timeout)
    if err or not text:
        return {"certs": [], "san_siblings": [], "error": err or "empty response"}
    try:
        rows = json.loads(text)
    except Exception:
        # crt.sh occasionally returns concatenated objects — wrap into an array
        try:
            rows = json.loads("[" + text.replace("}\n{", "},{") + "]")
        except Exception as e:  # noqa: BLE001
            return {"certs": [], "san_siblings": [], "error": f"parse: {e}"}

    certs, siblings, seen = [], set(), set()
    tgt = domain.lower().lstrip("*.")
    for row in rows[:cap] if isinstance(rows, list) else []:
        cid = str(row.get("id", "")).strip()
        if cid and cid not in seen:
            seen.add(cid)
            certs.append({
                "crtsh_id": cid,
                "serial_number": str(row.get("serial_number", "")).strip(),
                "not_before": row.get("not_before", ""),
                "not_after": row.get("not_after", ""),
                "issuer": (row.get("issuer_name", "") or "")[:120],
            })
        for name in str(row.get("name_value", "")).splitlines():
            n = name.strip().lower().lstrip("*.")
            if n and n != tgt and "." in n and not n.endswith(".arpa"):
                siblings.add(n)
    return {"certs": certs, "san_siblings": sorted(siblings)}


# ---------------------------------------------------- passive links + engine queries
def build_queries(sha1, sha256):
    q = {}
    if sha256:
        # Shodan's ssl.cert.fingerprint matches the SHA-256 fingerprint on modern data.
        q["shodan"] = f"ssl.cert.fingerprint:{sha256}"
        q["censys"] = f'services.tls.certificates.leaf_data.fingerprint_sha256="{sha256}"'
        q["fofa"] = f'cert="{sha256}"'
    if sha1:
        q["shodan_sha1"] = f"ssl.cert.fingerprint:{sha1}"
    return q


def passive_links(domain, sha1, sha256, crtsh_id="", serial=""):
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
        links.append({"engine": "censys_web", "label": "Censys host cert fingerprint (SHA-256)",
                      "url": ("https://search.censys.io/search?resource=hosts&q="
                              "services.tls.certificates.leaf_data.fingerprint_sha256%3D" + sha256)})
        fofa_b64 = base64.b64encode(f'cert="{sha256}"'.encode()).decode()
        links.append({"engine": "fofa_web", "label": "FOFA cert fingerprint (SHA-256)",
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
        text, err = _get(url, timeout=1800)
        if err or not text:
            continue
        try:
            data = json.loads(text)
        except Exception:
            continue
        for m in (data.get("matches") or [])[:cap]:
            ip = m.get("ip_str", "")
            hits.append({"engine": "shodan", "query": f"ssl.cert.fingerprint:{fp}",
                         "matched_ip": ip, "matched_host": "",
                         "url": f"https://www.shodan.io/host/{ip}" if ip else ""})
        if hits:
            break  # sha256 succeeded; don't double-count with sha1
    return hits, (None if hits else "no results / auth failure")


def censys_pivot(sha256, cap=20):
    # Accept either classic v2 basic auth (CENSYS_API_ID + CENSYS_API_SECRET) or a
    # Censys Platform personal-access-token bearer (CENSYS_API_KEY) — matches /apikeys.
    cid, csec = _secret("CENSYS_API_ID"), _secret("CENSYS_API_SECRET")
    bearer = _secret("CENSYS_API_KEY")
    if not sha256 or (not (cid and csec) and not bearer):
        return [], "no CENSYS_API_ID/SECRET or CENSYS_API_KEY (skipped)"
    q = f'services.tls.certificates.leaf_data.fingerprint_sha256="{sha256}"'
    url = f"https://search.censys.io/api/v2/hosts/search?q={quote(q)}&per_page={cap}"
    if cid and csec:
        auth = base64.b64encode(f"{cid}:{csec}".encode()).decode()
        headers = {"Authorization": f"Basic {auth}"}
    else:
        headers = {"Authorization": f"Bearer {bearer}"}
    text, err = _get(url, timeout=1800, headers=headers)
    if err or not text:
        return [], err or "empty response"
    try:
        data = json.loads(text)
    except Exception as e:  # noqa: BLE001
        return [], f"parse: {e}"
    hits = []
    for h in ((data.get("result") or {}).get("hits") or [])[:cap]:
        ip = h.get("ip", "")
        hits.append({"engine": "censys", "query": q, "matched_ip": ip,
                     "matched_host": "", "url": f"https://search.censys.io/hosts/{ip}" if ip else ""})
    return hits, (None if hits else "no results")


# --------------------------------------------------------------------------- driver
def run(domain=None, sha1="", sha256="", live=True, use_crtsh=True, cap=20):
    result = {"target": domain, "fingerprints": {}, "crtsh": {},
              "passive_links": [], "queries": {}, "active_pivots": [],
              "new_hosts": [], "notes": [], "summary": {}}

    if domain and live and not (sha1 or sha256):
        fp = fetch_leaf_fingerprints(domain)
        if "error" in fp:
            result["notes"].append(f"live cert fetch: {fp['error']}")
        else:
            sha1, sha256 = fp["sha1"], fp["sha256"]
    result["fingerprints"] = {"sha1": sha1, "sha256": sha256}

    crtsh_id = serial = ""
    if domain and use_crtsh:
        ch = crtsh_history(domain)
        result["crtsh"] = ch
        if ch.get("error"):
            result["notes"].append(f"crt.sh: {ch['error']}")
        if ch.get("certs"):
            crtsh_id = ch["certs"][0].get("crtsh_id", "")
            serial = ch["certs"][0].get("serial_number", "")
        result["new_hosts"].extend(ch.get("san_siblings", []))

    result["queries"] = build_queries(sha1, sha256)
    result["passive_links"] = passive_links(domain or "", sha1, sha256, crtsh_id, serial)

    sh_hits, sh_note = shodan_pivot(sha256, sha1, cap=cap)
    cn_hits, cn_note = censys_pivot(sha256, cap=cap)
    result["active_pivots"] = sh_hits + cn_hits
    for note in (sh_note, cn_note):
        if note:
            result["notes"].append(note)
    for h in result["active_pivots"]:
        ip = h.get("matched_ip")
        if ip and ip not in result["new_hosts"]:
            result["new_hosts"].append(ip)

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
    ap.add_argument("--no-live", action="store_true", help="skip live cert fetch")
    ap.add_argument("--no-crtsh", action="store_true", help="skip crt.sh history + SAN pivot")
    ap.add_argument("--cap", type=int, default=20, help="max results per active pivot query")
    ap.add_argument("--pretty", action="store_true", help="pretty-print JSON")
    ap.add_argument("-o", "--out", help="write JSON to file")
    args = ap.parse_args()

    if not args.domain and not (args.sha1 or args.sha256):
        ap.error("provide a domain, or --sha1/--sha256")

    result = run(domain=args.domain, sha1=args.sha1.lower(), sha256=args.sha256.lower(),
                 live=not args.no_live, use_crtsh=not args.no_crtsh, cap=args.cap)

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
