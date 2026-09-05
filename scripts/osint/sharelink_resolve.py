#!/usr/bin/env python3
"""sharelink_resolve.py — expand a short/share link and read what the sharer left in it.

Backs /sharelink. A share link handed over in chat (vm.tiktok.com/…, t.co/…, bit.ly/…) is not just
a redirect: platforms embed the SHARER'S identity in the tracking parameters, so the expanded URL
frequently names the account that sent it.

Follows the redirect chain with HEAD/GET and reads headers only — it never renders the page, never
runs JavaScript, and stops at a bounded hop count. The final host is contacted, so this is the one
tool here that is not purely passive; that is stated rather than buried.

Usage:
  sharelink_resolve.py https://vm.tiktok.com/ABCDEF/
  sharelink_resolve.py https://bit.ly/xxxx --max-hops 5 --pretty
"""
# /// script
# requires-python = ">=3.9"
# ///
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (compatible; cti-expert/sharelink_resolve)"

# Parameters that carry the SHARER's identity rather than the content's.
SHARER_PARAMS = {
    "u_code": "TikTok sharer user code", "user_id": "sharer user id",
    "share_app_id": "originating app", "share_link_id": "share event id",
    "sec_user_id": "TikTok secure user id", "shareId": "share event id",
    "si": "YouTube share session", "utm_source": "campaign source",
    "utm_campaign": "campaign name", "igshid": "Instagram share id",
    "fbclid": "Facebook click id", "ref": "referrer tag", "ref_src": "referrer source",
    "referrer": "referrer", "invite": "invite code", "inviteCode": "invite code",
    "affiliate": "affiliate id", "aff": "affiliate id", "agent": "agent id",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def hop(url, timeout=15):
    op = urllib.request.build_opener(_NoRedirect)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
        with op.open(req, timeout=timeout) as r:
            return r.getcode(), dict(r.headers), None
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), None
    except Exception as e:  # noqa: BLE001
        return None, {}, type(e).__name__


def main():
    ap = argparse.ArgumentParser(description="Expand a share/short link and extract sharer identity.")
    ap.add_argument("url")
    ap.add_argument("--max-hops", type=int, default=8)
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    url, chain, err = a.url.strip(), [], None
    for _ in range(max(1, a.max_hops)):
        code, hdrs, e = hop(url)
        if e:
            err = e
            break
        loc = hdrs.get("Location") or hdrs.get("location")
        chain.append({"url": url, "status": code, "location": loc})
        if not loc or not (300 <= (code or 0) < 400):
            break
        url = urllib.parse.urljoin(url, loc)

    q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    identity = [{"param": k, "value": v[0], "meaning": SHARER_PARAMS[k]}
                for k, v in q.items() if k in SHARER_PARAMS and v]
    out = {"input": a.url, "final_url": url, "hops": len(chain), "chain": chain,
           "sharer_identity": identity,
           "all_params": {k: v[0] for k, v in q.items()},
           "opsec": ("The FINAL host was contacted to resolve the redirect — this is not a purely "
                     "passive lookup and the operator's logs will show the request. Use a "
                     "research egress for adversarial infrastructure."),
           "caveat": ("A sharer parameter identifies the ACCOUNT THAT GENERATED THE LINK, which "
                      "is not necessarily the person who sent it to you — links get forwarded.")}
    if err:
        out["error"] = err
        out["verdict"] = f"chain incomplete ({err}) — the final URL may not be the true target"
    else:
        out["verdict"] = (f"resolved in {len(chain)} hop(s); "
                          f"{len(identity)} sharer-identity parameter(s)")
    print(f"{a.url} -> {url}  [{len(chain)} hop(s), {len(identity)} identity param(s)]",
          file=sys.stderr)
    for i in identity:
        print(f"  {i['param']}={i['value']}  ({i['meaning']})", file=sys.stderr)
    txt = json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)
    print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
