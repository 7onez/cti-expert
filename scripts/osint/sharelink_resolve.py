#!/usr/bin/env python3
"""sharelink_resolve.py — expand a short/share link and read what the sharer left in it.

Backs /sharelink. A share link handed over in chat (vm.tiktok.com/…, t.co/…, bit.ly/…,
facebook.com/share/r/…) is not just a redirect: platforms embed the SHARER'S identity in the
tracking parameters, so the expanded URL frequently names the account that sent it.

Follows the redirect chain with GET and reads headers only — it never renders the page, never
runs JavaScript, and stops at a bounded hop count. The final host is contacted, so this is the one
tool here that is not purely passive; that is stated rather than buried. `--no-follow` parses a URL
you already hold (e.g. a login-wall URL an analyst pasted) without contacting anything.

A chain that ends on a LOGIN WALL is not a dead end: the wall carries the content URL inside a
redirect-carrier parameter (`/login/?next=<encoded url with story_fbid=…&id=…>`). Every layer is
unwrapped recursively (next / u / url / redirect_uri / continue / target …, bounded depth,
double-encoding tolerated) and the platform IDs found on ANY layer are returned as a structured
`platform_ids` block — Facebook page/profile id, story_fbid, fbid, reel/video id, share token;
Instagram shortcode, username, igshid; TikTok video id, @user, sec_user_id.

Usage:
  sharelink_resolve.py https://vm.tiktok.com/ABCDEF/
  sharelink_resolve.py https://bit.ly/xxxx --max-hops 5 --pretty
  sharelink_resolve.py 'https://www.facebook.com/login/?next=…' --no-follow
"""
# /// script
# requires-python = ">=3.9"
# ///
import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

# Android Chrome (project decision: web requests present as an Android device).
UA = ("Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36")

# Parameters that carry the SHARER's identity rather than the content's.
SHARER_PARAMS = {
    "u_code": "TikTok sharer user code", "user_id": "sharer user id",
    "share_app_id": "originating app", "share_link_id": "share event id",
    "sec_user_id": "TikTok secure user id", "shareId": "share event id",
    "si": "YouTube share session", "utm_source": "campaign source",
    "utm_campaign": "campaign name", "igshid": "Instagram share id", "igsh": "Instagram share id",
    "fbclid": "Facebook click id", "mibextid": "Facebook share-sheet source id",
    "ref": "referrer tag", "ref_src": "referrer source",
    "referrer": "referrer", "invite": "invite code", "inviteCode": "invite code",
    "affiliate": "affiliate id", "aff": "affiliate id", "agent": "agent id",
}

# Parameters whose VALUE is another URL (login walls, interstitials, link shims). Unwrapped
# recursively up to MAX_UNWRAP_DEPTH so a wall-inside-a-shim still yields the content URL.
CARRIER_PARAMS = ("next", "u", "url", "redirect_uri", "redirect_url", "redirect", "continue",
                  "target", "return_to", "dest")
MAX_UNWRAP_DEPTH = 6

# Facebook first path segments that are routes, not a page/profile vanity.
_FB_RESERVED = {"login", "login.php", "share", "story.php", "permalink.php", "photo.php", "photo",
                "watch", "reel", "reels", "people", "profile.php", "groups", "pages", "events",
                "marketplace", "hashtag", "help", "policies", "privacy", "ads", "business",
                "dialog", "plugins", "sharer", "sharer.php", "l.php", "checkpoint", "recover",
                "settings", "home.php", "notifications", "messages", "stories", "gaming", "media",
                "video.php", "videos", "posts", "search", "friends", "bookmarks", "r.php", "tr",
                "public", "legal", "about", "terms", "cookie", "?"}
_IG_RESERVED = {"p", "reel", "reels", "tv", "stories", "explore", "accounts", "direct", "about",
                "legal", "developer", "web", "challenge", "emails", "api", "graphql", "s", "share"}
_HANDLE_RE = re.compile(r"^[A-Za-z0-9_.\-]{2,80}$")


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


def _as_url(value, base):
    """A carrier value → absolute URL, or None. Tolerates one extra layer of percent-encoding
    (`https%3A%2F%2F…`) and a site-relative path (`/story.php?…`, joined to the carrier's origin)."""
    v = (value or "").strip()
    for _ in range(2):
        if re.match(r"^https?%3A", v, re.I):
            v = urllib.parse.unquote(v)
    if re.match(r"^https?://", v, re.I):
        return v
    if v.startswith("/") and not v.startswith("//"):
        return urllib.parse.urljoin(base, v)
    if v.startswith("//"):
        return "https:" + v
    return None


def unwrap(url, max_depth=MAX_UNWRAP_DEPTH):
    """Every URL layer nested in `url` via carrier params, outermost first (the input included).
    Breadth over all carrier params at each layer; depth-bounded; never revisits a URL."""
    layers, seen, frontier = [], set(), [(url, 0, None)]
    while frontier:
        cur, depth, via = frontier.pop(0)
        if cur in seen:
            continue
        seen.add(cur)
        layers.append({"url": cur, "depth": depth, "via_param": via})
        if depth >= max_depth:
            continue
        try:
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(cur).query, keep_blank_values=False)
        except ValueError:
            continue
        for k in CARRIER_PARAMS:
            for val in q.get(k) or ():
                inner = _as_url(val, cur)
                if inner and inner not in seen:
                    frontier.append((inner, depth + 1, k))
    return layers


def _platform_of(host):
    h = (host or "").lower()
    for dom, name in (("facebook.com", "facebook"), ("fb.com", "facebook"), ("fb.watch", "facebook"),
                      ("fb.me", "facebook"), ("instagram.com", "instagram"),
                      ("instagr.am", "instagram"), ("tiktok.com", "tiktok")):
        if h == dom or h.endswith("." + dom):
            return name
    return None


def _set(out, key, value, url):
    if value and key not in out:
        out[key] = {"value": value, "seen_in": url}


def _facebook_ids(p, q, url, out):
    segs = [s for s in p.path.split("/") if s]
    host = (p.hostname or "").lower()
    if host.endswith("fb.watch") and segs:
        _set(out, "share_token", segs[0], url)
        _set(out, "share_kind", "video", url)
        return
    for key, field in (("story_fbid", "story_fbid"), ("fbid", "fbid"), ("v", "video_id"),
                       ("video_id", "video_id"), ("set", "media_set"), ("multi_permalinks", "post_id")):
        if q.get(key):
            _set(out, field, q[key][0], url)
    if q.get("id") and q["id"][0].isdigit():
        # story.php / permalink.php `id` is the OWNER (page or profile) of the story.
        _set(out, "owner_id", q["id"][0], url)
    if not segs:
        return
    s0 = segs[0].lower()
    if s0 == "share" and len(segs) >= 2:
        kinds = {"r": "reel", "v": "video", "p": "post", "g": "group"}
        if segs[1].lower() in kinds and len(segs) >= 3:
            _set(out, "share_kind", kinds[segs[1].lower()], url)
            _set(out, "share_token", segs[2], url)
        else:
            _set(out, "share_kind", "profile_or_page", url)
            _set(out, "share_token", segs[1], url)
    elif s0 in ("reel", "reels") and len(segs) >= 2 and segs[1].isdigit():
        _set(out, "reel_id", segs[1], url)
    elif s0 == "profile.php" and q.get("id"):
        _set(out, "profile_id", q["id"][0], url)
    elif s0 == "people" and len(segs) >= 3 and segs[2].isdigit():
        _set(out, "profile_id", segs[2], url)
    elif s0 == "pages" and len(segs) >= 3 and segs[-1].isdigit():
        _set(out, "page_id", segs[-1], url)
    elif s0 == "groups" and len(segs) >= 2:
        _set(out, "group", segs[1], url)
        if len(segs) >= 4 and segs[2] in ("posts", "permalink"):
            _set(out, "post_id", segs[3], url)
    elif s0 not in _FB_RESERVED and _HANDLE_RE.match(segs[0]):
        if segs[0].isdigit():
            _set(out, "page_or_profile_id", segs[0], url)
        else:
            _set(out, "vanity", segs[0], url)
        if len(segs) >= 3 and segs[1] in ("posts", "videos", "photos"):
            _set(out, {"posts": "post_id", "videos": "video_id", "photos": "photo_id"}[segs[1]],
                 segs[2], url)


def _instagram_ids(p, q, url, out):
    segs = [s for s in p.path.split("/") if s]
    for key in ("igshid", "igsh"):
        if q.get(key):
            _set(out, "igshid", q[key][0], url)
    if not segs:
        return
    s0 = segs[0].lower()
    if s0 in ("p", "reel", "reels", "tv") and len(segs) >= 2:
        _set(out, "shortcode", segs[1], url)
        _set(out, "media_kind", {"p": "post", "tv": "igtv"}.get(s0, "reel"), url)
    elif s0 == "stories" and len(segs) >= 2:
        _set(out, "username", segs[1], url)
        if len(segs) >= 3 and segs[2].isdigit():
            _set(out, "story_id", segs[2], url)
    elif s0 == "share" and len(segs) >= 2:
        _set(out, "share_token", segs[-1], url)
    elif s0 not in _IG_RESERVED and _HANDLE_RE.match(segs[0]):
        _set(out, "username", segs[0], url)
        if len(segs) >= 3 and segs[1] in ("p", "reel"):
            _set(out, "shortcode", segs[2], url)


def _tiktok_ids(p, q, url, out):
    segs = [s for s in p.path.split("/") if s]
    host = (p.hostname or "").lower()
    for key in ("sec_user_id", "u_code", "share_item_id", "share_author_id"):
        if q.get(key):
            _set(out, key, q[key][0], url)
    if host.split(".")[0] in ("vm", "vt") and segs:
        _set(out, "share_token", segs[0], url)
        return
    if not segs:
        return
    if segs[0].startswith("@"):
        _set(out, "user", segs[0][1:], url)
        if len(segs) >= 3 and segs[1] in ("video", "photo") and segs[2].isdigit():
            _set(out, "video_id", segs[2], url)
    elif segs[0] == "t" and len(segs) >= 2:
        _set(out, "share_token", segs[1], url)
    elif segs[0] == "v" and len(segs) >= 2:
        m = re.match(r"(\d{8,})", segs[1])
        if m:
            _set(out, "video_id", m.group(1), url)


def platform_ids(urls):
    """Platform IDs across every layer → {platform: {field: {value, seen_in}}}. First layer that
    names a field wins (the outermost wins ties), so `seen_in` cites where the value was read."""
    out = {}
    for url in urls:
        try:
            p = urllib.parse.urlsplit(url)
            q = urllib.parse.parse_qs(p.query)
        except ValueError:
            continue
        plat = _platform_of(p.hostname)
        if not plat:
            continue
        bucket = out.setdefault(plat, {})
        {"facebook": _facebook_ids, "instagram": _instagram_ids, "tiktok": _tiktok_ids}[plat](
            p, q, url, bucket)
    # story.php's `id` is a page OR a profile — say so instead of guessing which.
    fb = out.get("facebook") or {}
    if "owner_id" in fb:
        fb["owner_id"]["meaning"] = ("numeric owner of the story — a Page id or a profile id; "
                                     "resolve with meta_transparency to tell which")
    return {k: v for k, v in out.items() if v}


def _login_wall(url):
    path = urllib.parse.urlsplit(url).path.lower()
    return any(t in path for t in ("/login", "/checkpoint", "/accounts/login"))


def analyse(input_url, final_url):
    layers = unwrap(final_url)
    if input_url != final_url:
        layers = unwrap(input_url) + [l for l in layers if l["url"] != input_url]
    urls = [l["url"] for l in layers]
    identity, seen = [], set()
    for u in urls:
        for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(u).query).items():
            if k in SHARER_PARAMS and v and (k, v[0]) not in seen:
                seen.add((k, v[0]))
                identity.append({"param": k, "value": v[0], "meaning": SHARER_PARAMS[k],
                                 "seen_in": u})
    return layers, identity, platform_ids(urls)


def main():
    ap = argparse.ArgumentParser(description="Expand a share/short link and extract sharer identity.")
    ap.add_argument("url")
    ap.add_argument("--max-hops", type=int, default=8)
    ap.add_argument("--no-follow", action="store_true",
                    help="parse the given URL only — contact nothing (offline)")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    url, chain, err = a.url.strip(), [], None
    for _ in range(0 if a.no_follow else max(1, a.max_hops)):
        code, hdrs, e = hop(url)
        if e:
            err = e
            break
        loc = hdrs.get("Location") or hdrs.get("location")
        chain.append({"url": url, "status": code, "location": loc})
        if not loc or not (300 <= (code or 0) < 400):
            break
        url = urllib.parse.urljoin(url, loc)

    layers, identity, ids = analyse(a.url.strip(), url)
    q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    out = {"input": a.url, "final_url": url, "hops": len(chain), "chain": chain,
           "login_wall": any(_login_wall(l["url"]) for l in layers),
           "unwrapped": layers,
           "platform_ids": ids,
           "sharer_identity": identity,
           "all_params": {k: v[0] for k, v in q.items()},
           "opsec": ("Offline parse — nothing was contacted." if a.no_follow else
                     "The FINAL host was contacted to resolve the redirect — this is not a purely "
                     "passive lookup and the operator's logs will show the request. Use a "
                     "research egress for adversarial infrastructure."),
           "caveat": ("A sharer parameter identifies the ACCOUNT THAT GENERATED THE LINK, which "
                      "is not necessarily the person who sent it to you — links get forwarded. "
                      "A platform id names an ACCOUNT, never the person who runs it.")}
    n_ids = sum(len(v) for v in ids.values())
    if err:
        out["error"] = err
        out["verdict"] = f"chain incomplete ({err}) — the final URL may not be the true target"
    else:
        out["verdict"] = (f"resolved in {len(chain)} hop(s); {len(layers)} layer(s) unwrapped; "
                          f"{n_ids} platform id(s); {len(identity)} sharer-identity parameter(s)"
                          + ("; ended on a LOGIN WALL — ids read from its carrier params"
                             if out["login_wall"] else ""))
    print(f"{a.url} -> {url}  [{len(chain)} hop(s), {n_ids} platform id(s), "
          f"{len(identity)} identity param(s)]", file=sys.stderr)
    for plat, fields in ids.items():
        for k, v in fields.items():
            print(f"  {plat}.{k}={v['value']}", file=sys.stderr)
    for i in identity:
        print(f"  {i['param']}={i['value']}  ({i['meaning']})", file=sys.stderr)
    txt = json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)
    print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
