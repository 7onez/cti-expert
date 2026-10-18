#!/usr/bin/env python3
"""The three keys that used to sit in .env and never leave it must be attached,
and must not be sent when absent. Network is stubbed — a down vendor must not
redden this gate.
"""
import importlib.util
import json
import os
import pathlib
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load():
    p = ROOT / "scripts" / "osint" / "keyed_feeds.py"
    spec = importlib.util.spec_from_file_location("keyed_feeds", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


kf = load()
LEDGER = []   # the real api_usage ledger must never grow from a mocked suite (run_eval spend guard)
kf._ledger = lambda provider, action, query, **k: LEDGER.append((provider, action, query, k))
FAIL = []


def check(cond, msg):
    if not cond:
        FAIL.append(msg)


class _Resp:
    def __init__(self, body, code=200):
        self._body = body
        self._code = code

    def read(self, _n=None):
        return self._body

    def getcode(self):
        return self._code

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


CAPTURED = []


def _install(body=b'{"query_status":"ok","data":[]}', code=200):
    CAPTURED.clear()

    def _urlopen(req, timeout=20):
        CAPTURED.append(req)
        return _Resp(body, code)

    urllib.request.urlopen = _urlopen


def _clear(*names):
    for n in names:
        os.environ.pop(n, None)


# ── absent key: zero requests ──────────────────────────────────────────────
_clear("ABUSE_CH_API_KEY", "ABUSECH_API_KEY", "URLHAUS_AUTH_KEY",
       "HUDSONROCK_API_KEY", "HUDSON_ROCK_API_KEY",
       "ZONECRUNCHER_API_KEY", "ZETALYTICS_API_KEY", "ZETALYTICS_TOKEN")
kf._LOADED = True  # do not pull the real .env into this process
_install()
check(kf.abusech_lookup("example.com", "domain")["status"].startswith("NOT CONSULTED"),
      "abuse.ch with no key must be NOT CONSULTED")
check(kf.hudsonrock_lookup("user@example.com")["status"].startswith("NOT CONSULTED"),
      "Hudson Rock with no key must be NOT CONSULTED")
check(kf.zonecruncher_lookup("example.com")["status"].startswith("NOT CONSULTED"),
      "ZoneCruncher with no key must be NOT CONSULTED")
check(CAPTURED == [], "a missing key must not open a socket")

# ── abuse.ch: Auth-Key header on both feeds ────────────────────────────────
_install()
os.environ["ABUSE_CH_API_KEY"] = "abuse-test-key"
out = kf.abusech_lookup("example.com", "domain")
check(out["auth"] == "Auth-Key", "abuse.ch must report Auth-Key auth")
check(len(CAPTURED) == 2, "domain lookup must hit URLhaus and ThreatFox")
for req in CAPTURED:
    check(req.get_header("Auth-key") == "abuse-test-key" or
          req.headers.get("Auth-Key") == "abuse-test-key",
          "Auth-Key header missing on %s" % req.full_url)
    check("abuse-test-key" not in req.full_url, "Auth-Key must not be placed in the URL")
check(any("urlhaus-api.abuse.ch" in r.full_url for r in CAPTURED), "URLhaus not called")
check(any("threatfox-api.abuse.ch" in r.full_url for r in CAPTURED), "ThreatFox not called")

# ── Hudson Rock: api-key header, passwords stripped, key not in the URL ───
_install(json.dumps({"data": [{"stealer_family": "redline", "password": "s3cret",
                               "date_compromised": "2024-01-01"}]}).encode())

# ── deep_profile sends Hudson Rock and ZoneCruncher when the keys are set ──
import importlib.util as _ilu
import io
_spec = _ilu.spec_from_file_location("deep_profile", ROOT / "scripts" / "osint" / "deep_profile.py")
dp = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(dp)
dp.run = lambda *a, **k: {"status": "skipped"}
sent = []
dp.keyed_feeds.hudsonrock_lookup = lambda *a, **k: sent.append("hr") or {"status": "ok"}
dp.keyed_feeds.zonecruncher_lookup = lambda *a, **k: sent.append("zc") or {"status": "ok"}
dp.keyed_feeds.load_keys = lambda: None
os.environ["HUDSONROCK_API_KEY"] = "hr-test-key"
os.environ["ZONECRUNCHER_API_KEY"] = "zeta-test-token-32chars-pad!!"
buf = io.StringIO()
old_argv, old_out = sys.argv, sys.stdout
sys.argv = ["deep_profile.py", "user@example.com", "--mode", "breach"]
sys.stdout = buf
try:
    dp.main()
finally:
    sys.stdout = old_out
    sys.argv = old_argv
check(sent == ["hr", "zc"], "a key in the environment must be sent, not held")
planned = {p["step"]: p["status"] for p in json.loads(buf.getvalue())["planned"]}
check(planned.get("hudsonrock") == "RAN — key set and this selector needs it", "hudsonrock plan row must say it ran")
check(planned.get("zonecruncher") == "RAN — key set and this selector needs it", "zonecruncher plan row must say it ran")
sent.clear()
os.environ.pop("HUDSONROCK_API_KEY", None)
os.environ.pop("ZONECRUNCHER_API_KEY", None)
sys.argv = ["deep_profile.py", "user@example.com", "--mode", "breach"]
sys.stdout = open(os.devnull, "w")
try:
    dp.main()
finally:
    sys.stdout.close()
    sys.stdout = old_out
    sys.argv = old_argv
check(sent == [], "absent keys must not be sent")
os.environ["HUDSONROCK_API_KEY"] = "hr-test-key"
os.environ["ZONECRUNCHER_API_KEY"] = "zeta-test-token-32chars-pad!!"
sys.argv = ["deep_profile.py", "user@example.com", "--mode", "breach", "--free-only"]
sys.stdout = open(os.devnull, "w")
try:
    dp.main()
finally:
    sys.stdout.close()
    sys.stdout = old_out
    sys.argv = old_argv
check(sent == [], "--free-only must hold every metered send")
os.environ.pop("HUDSONROCK_API_KEY", None)
os.environ.pop("ZONECRUNCHER_API_KEY", None)
os.environ["HUDSONROCK_API_KEY"] = "hr-test-key"
out = kf.hudsonrock_lookup("user@example.com")
check(out["status"] == "ok" and out["auth"] == "api-key", "Hudson Rock must send api-key and return ok")
check(out["hits"] == 1, "Hudson Rock hit count must survive redaction")
check(out["records"][0].get("password") is None, "stealer password must be stripped")
check(out["records"][0].get("stealer_family") == "redline", "non-secret fields must be kept")
req = CAPTURED[0]
check(req.get_header("Api-key") == "hr-test-key" or req.headers.get("api-key") == "hr-test-key",
      "api-key header missing")
check("hr-test-key" not in req.full_url, "Hudson Rock key must not be in the URL")
check(req.full_url.endswith("/search-by-login/emails"), "email selector must hit the email endpoint")
body = json.loads(req.data.decode())
check(body["logins"] == ["user@example.com"], "email must be the POST body, not a query string")

# ── ZoneCruncher: token query param, scrubbed from errors ──────────────────
_install(json.dumps({"results": [{"domain": "other.example"}]}).encode())
os.environ["ZONECRUNCHER_API_KEY"] = "zeta-test-token-32chars-pad!!"
out = kf.zonecruncher_lookup("reg@example.com")
check(out["status"] == "ok" and out["auth"] == "token", "ZoneCruncher must send the token")
check(out["endpoint"] == "email_address", "an email must hit email_address")
check("other.example" in out["values"], "reverse-email domain must be returned")
req = CAPTURED[0]
check("token=zeta-test-token-32chars-pad%21%21" in req.full_url or
      "token=zeta-test-token-32chars-pad!!" in req.full_url,
      "token query param missing")
check("zeta-test-token" not in json.dumps(out), "token must not echo into the result")
check(("zonecruncher", "email_address", "reg@example.com", {"results": 1}) in LEDGER,
      "a ZoneCruncher call must be recorded in the api_usage ledger")
check(any(r[0] == "hudsonrock" for r in LEDGER),
      "a Hudson Rock call must be recorded in the api_usage ledger")

# ── Spamhaus SIA: login once, token reused, 404 = no data, fallback-only in reputation_check ──
import tempfile  # noqa: E402
import time as _time  # noqa: E402
_tmpdir = tempfile.mkdtemp()
kf._SPAMHAUS_TOKEN_FILE = os.path.join(_tmpdir, "token.json")
_clear("SPAMHAUS_USERNAME", "SPAMHAUS_USER", "SPAMHAUS_PASSWORD", "SPAMHAUS_PASS", "CTI_FREE_ONLY")
_install()
check(kf.spamhaus_lookup("192.0.2.10", "ip")["status"].startswith("NOT CONSULTED"),
      "Spamhaus with no credentials must be NOT CONSULTED")
check(CAPTURED == [], "missing Spamhaus credentials must not open a socket")

os.environ["SPAMHAUS_USERNAME"] = "analyst@example.com"
os.environ["SPAMHAUS_PASSWORD"] = "sh-test-pass"
_now = int(_time.time())
_ROUTES = {
    "/api/v1/login": (200, {"code": 200, "token": "sh-tok", "expires": _now + 86400}),
    "/cidr/ALL/listed/history/192.0.2.10": (200, {"code": 200, "results": [
        {"dataset": "XBL", "listed": _now - 3600, "valid_until": _now + 3600, "detection": "x"},
        {"dataset": "CSS", "listed": _now - 90 * 86400, "valid_until": _now - 80 * 86400}]}),
    "/cidr/ALL/listed/history/192.0.2.20": (404, {"code": 404}),
    "/domain/bad.example/listing": (200, {"ts": _now, "is-listed": True, "listed-until": _now + 999}),
    "/domain/bad.example": (200, {"domain": "bad.example", "score": -6.1, "tags": ["phish"],
                                   "abused": False}),
    # shape measured live on example.com: phish/spam tags on a GOOD reputation (+34.3)
    "/domain/popular.example/listing": (200, {"ts": _now, "is-listed": False}),
    "/domain/popular.example": (200, {"domain": "popular.example", "score": 34.3,
                                       "tags": ["phish", "spam"], "abused": False}),
}


def _route_urlopen(req, timeout=20):
    CAPTURED.append(req)
    for frag, (code, body) in sorted(_ROUTES.items(), key=lambda kv: -len(kv[0])):
        if frag in req.full_url:
            if code >= 400:
                raise urllib.error.HTTPError(req.full_url, code, "x", {}, io.BytesIO(json.dumps(body).encode()))
            return _Resp(json.dumps(body).encode(), code)
    raise AssertionError("unexpected URL " + req.full_url)


import urllib.error  # noqa: E402
CAPTURED.clear()
urllib.request.urlopen = _route_urlopen
ip = kf.spamhaus_lookup("192.0.2.10", "ip")
check(ip["status"] == "ok" and ip["active_datasets"] == ["XBL"] and ip["history_count"] == 2,
      "an active XBL row is active; an expired CSS row is history only")
logins = [r for r in CAPTURED if r.full_url.endswith("/api/v1/login")]
check(len(logins) == 1, "first call logs in exactly once")
check(json.loads(logins[0].data.decode())["realm"] == "intel", "login must send realm=intel")
check(all(r.get_header("Authorization") == "Bearer sh-tok" for r in CAPTURED if "login" not in r.full_url),
      "queries must carry the bearer token")
CAPTURED.clear()
clean = kf.spamhaus_lookup("192.0.2.20", "ip")
check(clean["status"] == "ok" and clean["history_count"] == 0, "Spamhaus HTTP 404 = no data, not an error")
check(not any("login" in r.full_url for r in CAPTURED), "a cached token must be reused, not re-logged-in")
dom = kf.spamhaus_lookup("bad.example", "domain")
check(dom["listed"] is True and dom["tags"] == ["phish"], "domain listing + tags must be parsed")
check(all("sh-test-pass" not in json.dumps(x) for x in (ip, clean, dom)), "password must never echo")
os.environ["CTI_FREE_ONLY"] = "1"
CAPTURED.clear()
check(kf.spamhaus_lookup("192.0.2.10", "ip")["status"] == "ok" and CAPTURED,
      "the free Developer License is not a metered credit: --free-only must not hold Spamhaus")
os.environ.pop("CTI_FREE_ONLY", None)

_rspec = importlib.util.spec_from_file_location("reputation_check", ROOT / "scripts" / "osint" / "reputation_check.py")
rc = importlib.util.module_from_spec(_rspec)
_rspec.loader.exec_module(rc)
rc.keyed_feeds = kf
for _f in ("otx", "urlscan", "virustotal", "abuseipdb", "chongluadao"):
    setattr(rc, _f, lambda ind, kind: {"status": "ok", "pulse_count": 0, "recent": []})
called = []
_real_sh = kf.spamhaus_lookup
kf.spamhaus_lookup = lambda t, k: called.append((t, k)) or _real_sh(t, k)
kf.abusech_lookup = lambda ind, kind: {"status": "ok", "listed": False}


def _rc(ind):
    buf = io.StringIO()
    saved_argv, saved_out, saved_err = sys.argv, sys.stdout, sys.stderr
    sys.argv, sys.stdout, sys.stderr = ["reputation_check.py", ind], buf, io.StringIO()
    try:
        rc.main()
    finally:
        sys.argv, sys.stdout, sys.stderr = saved_argv, saved_out, saved_err
    return json.loads(buf.getvalue())


r = _rc("192.0.2.10")
check(called == [("192.0.2.10", "ip")], "no primary signal → Spamhaus fallback must run")
check(any("Spamhaus: currently listed on XBL" in s for s in r["signals"]) and r["verdict"] == "SUSPICIOUS",
      "an active Spamhaus listing is a scored signal")
check(len(r.get("notes") or []) == len(set(r.get("notes") or [])), "re-verdict must not duplicate notes")
called.clear()
r = _rc("https://www.bad.example/login")
check(called == [("bad.example", "domain")], "a URL falls back on its registrable domain, not the host")
check(any("Spamhaus DBL: domain currently listed" in s for s in r["signals"]),
      "a current DBL listing is a scored signal")
rc.urlscan = lambda ind, kind: {"status": "ok", "recent": [{"verdict_malicious": True}]}
called.clear()
r = _rc("popular.example")
check(called == [("popular.example", "domain")], "a single-feed SUSPICIOUS still falls back")
check(r["verdict"] == "SUSPICIOUS" and not any("Spamhaus" in s for s in r["signals"]),
      "phish/spam tags on a POSITIVE score must not be scored or upgrade the verdict")
check(any("not negative" in n for n in r.get("notes") or []),
      "tags on a positive score are reported as a note")
rc.otx = lambda ind, kind: {"status": "ok", "pulse_count": 9, "recent": []}
rc.urlscan = lambda ind, kind: {"status": "ok", "recent": [{"verdict_malicious": True}]}
called.clear()
r = _rc("bad.example")
check(called == [] and r["sources"]["spamhaus"]["status"].startswith("NOT NEEDED"),
      "primary feeds already MALICIOUS → Spamhaus quota is not spent")

# a Spamhaus malware/botnet tag is partly abuse.ch-derived: never the 'second independent feed'
res = {"sources": {"abusech": {"status": "ok", "listed": True, "listed_on": ["threatfox"]},
                   "spamhaus": {"status": "ok", "kind": "domain", "score": -5,
                                "tags": ["botnetcc"], "listed": False}}}
v = rc.verdict(res, "threat")
check(v["verdict"] == "SUSPICIOUS" and len(v["signals"]) == 1,
      "abuse.ch + abuse.ch-derived Spamhaus tag must not read as 2 independent feeds")
check(any("partly" in n for n in res.get("notes") or []), "the derived tag is reported as a note")

# sinkhole/neverlist override: a defender's sinkhole carries botnetcc on a negative score
res = {"sources": {"otx": {"status": "ok", "pulse_count": 0},
                   "spamhaus": {"status": "ok", "kind": "domain", "score": -8,
                                "tags": ["sinkhole", "botnetcc"], "listed": False}}}
v = rc.verdict(res, "threat")
check(v["verdict"] == "NO ADVERSE RECORD" and not v["signals"],
      "sinkhole + botnetcc (score -8) must never be scored")
check(any("sinkhole" in n and "not scored" in n for n in res.get("notes") or []),
      "the override is reported as a note")

if FAIL:
    for f in FAIL:
        print("FAIL: " + f, file=sys.stderr)
    raise SystemExit(1)
print("keyed feeds: key attached when set, absent when not, passwords stripped")
