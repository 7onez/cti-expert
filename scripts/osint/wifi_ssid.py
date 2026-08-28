#!/usr/bin/env python3
"""wifi_ssid.py — geolocate a WiFi SSID via WiGLE, and say so plainly when it cannot.

Backs /wifi. WiGLE is the only usable corpus of wardriven SSID observations and it requires an
account: there is no keyless path, so without WIGLE_API_NAME / WIGLE_API_TOKEN this returns the
exact query to run rather than an empty result that reads like "no such network".

Ethics, because this one is sharper than the rest: an SSID observation is a HOME OR WORKPLACE
LOCATION for whoever runs that access point. A distinctive SSID usually resolves to a private
residence. Use it for infrastructure attribution, not to locate a person, and treat a hit as
sensitive personal data under your own retention rules.

Usage:
  wifi_ssid.py "SomeNetworkName"
  wifi_ssid.py "SomeNetworkName" --pretty
"""
# /// script
# requires-python = ">=3.9"
# ///
import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = "cti-expert/wifi_ssid (OSINT research)"
API = "https://api.wigle.net/api/v2/network/search"


def main():
    ap = argparse.ArgumentParser(description="WiGLE SSID geolocation (needs a WiGLE account).")
    ap.add_argument("ssid")
    ap.add_argument("--max", type=int, default=20)
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    ssid = a.ssid.strip()
    name = os.environ.get("WIGLE_API_NAME")
    token = os.environ.get("WIGLE_API_TOKEN")
    q = urllib.parse.urlencode({"ssid": ssid, "resultsPerPage": min(a.max, 100)})

    out = {"ssid": ssid,
           "ethics": ("An SSID observation is a HOME OR WORKPLACE location for whoever runs the "
                      "access point. Use it for infrastructure attribution, not to locate a "
                      "person; handle any hit as sensitive personal data.")}

    if not (name and token):
        out["status"] = "NOT QUERIED — no WiGLE credentials"
        out["collection_gap"] = ("WIGLE_API_NAME / WIGLE_API_TOKEN are unset. There is no keyless "
                                 "path to this corpus, so this is an absence of COLLECTION — it "
                                 "is not evidence the SSID was never observed.")
        out["how_to_enable"] = ["register at https://wigle.net/account",
                                "/apikeys set wigle_api_name <name>",
                                "/apikeys set wigle_api_token <token>"]
        out["manual_query"] = f"https://wigle.net/search?ssid={urllib.parse.quote(ssid)}"
        print(f"{ssid}: NOT QUERIED — no WiGLE credentials (this is a collection gap, not a "
              f"negative result)", file=sys.stderr)
        txt = json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False)
        if a.out:
            open(a.out, "w", encoding="utf-8").write(txt)
        print(txt)
        return 0

    auth = base64.b64encode(f"{name}:{token}".encode()).decode()
    try:
        req = urllib.request.Request(f"{API}?{q}",
                                     headers={"User-Agent": UA, "Authorization": f"Basic {auth}"})
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.load(r)
    except urllib.error.HTTPError as e:
        out["status"] = f"unavailable (HTTP {e.code})"
        if e.code == 401:
            out["hint"] = "WiGLE credentials rejected — check the name/token pair"
        print(json.dumps(out)); return 0
    except Exception as e:  # noqa: BLE001
        out["status"] = f"unavailable ({type(e).__name__})"
        print(json.dumps(out)); return 0

    res = d.get("results") or []
    out["status"] = "ok"
    out["matches"] = [{"ssid": r.get("ssid"), "bssid": r.get("netid"),
                       "lat": r.get("trilat"), "lon": r.get("trilong"),
                       "first_seen": r.get("firsttime"), "last_seen": r.get("lasttime"),
                       "country": r.get("country"), "region": r.get("region"),
                       "city": r.get("city")} for r in res[:a.max]]
    out["count"] = len(out["matches"])
    out["total_reported"] = d.get("totalResults")
    out["caveat"] = ("A common SSID (default router names, 'linksys', a cafe chain) matches many "
                     "unrelated networks — only a DISTINCTIVE SSID narrows to one site.")
    print(f"{ssid}: {out['count']} observation(s) of {out.get('total_reported')}", file=sys.stderr)
    txt = json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)
    print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
