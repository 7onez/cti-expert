#!/usr/bin/env python3
"""wp_meta — keyless Meta account TRANSPARENCY collector (meta_transparency).

Input a Facebook Page (vanity, numeric id, or any facebook.com URL) or an Instagram account
(@handle / instagram.com URL / `--platform instagram`) and collect what Meta publishes about the
ACCOUNT without a login:

  Facebook  the Page plugin (vanity → numeric Page id, name, followers), then the Ad Library page
            view, whose About tab — re-requested through the page's own GraphQL preloader with
            isAboutTab=true — carries the Page-transparency block: creation date, name-change and
            merge DATES, admin-location country counts, the confirmed owning organisation, the
            linked Instagram account, category, about text, likes, active/total ad counts, pages
            sharing an ad disclaimer, and the page_name each sampled ad ran under (an Ad-Library
            name history with dates).
  Instagram the public web-profile JSON: full name, bio, bio links, external URL, category,
            business contact email/phone/address when the account publishes them, linked FB id,
            counts. 'About this account' (date joined, country, former usernames) is login-only
            and is reported as such, never worked around.
  History   name / username / bio / location / external URL / category reconstructed from Wayback
            captures of the canonical profile URL (wp_wayback client + run-scoped breaker), plus the
            Ad Library name history.

Tri-state per field, never raises: every field is {status, value, source, captured_at}, status ∈
found | not_exposed | login_required | blocked | rate_limited | error. A 429 / GraphQL 1675004 is
retried with exponential backoff and an honoured Retry-After (bounded by reference data; a longer
wait comes back as rate_limited with the server's retry_after — never a local usage cap).

NO COOKIES, EVER: no analyst cookie, session token or login is accepted or used. The only cookie
in play is the anonymous challenge cookie Meta's edge hands every logged-out visitor, held in
memory for this one run. Anything behind a login is returned as an ANALYST CAPTURE CHECKLIST
(which panels to screenshot while logged in) — the tool never asks for credentials.

Attribution rail: every value is an ACCOUNT-level fact (what the platform says about the account),
never an owner/person attribution. Read-only; contacts facebook.com / instagram.com / archive.org.
Keyless, so it runs under free_only / no_spend. Reference DATA: references/meta_transparency.json.

CLI:
  python3 wp_meta.py https://www.facebook.com/examplepage --case CASE-0001
  python3 wp_meta.py 100000000000001 --json
  python3 wp_meta.py @operator-a --platform instagram --no-wayback
  python3 wp_meta.py --search "Example Brand"
"""
import argparse
import datetime as _dt
import html
import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.dirname(os.path.dirname(HERE))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import wp_common  # noqa: E402,F401 — installs the process-global egress proxy
from wp_common import _decode_body  # noqa: E402
from wp_refs import ref_path, load_ref  # noqa: E402

_FALLBACK = {
    "settings": {"ua": "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36",
                 "timeout_seconds": 30, "attempts": 2, "backoff_seconds": 5,
                 "max_retry_after_seconds": 60, "country": "ALL",
                 "max_related_pages": 20, "max_ads_sampled": 20},
    "endpoints": {
        "page_plugin": "https://www.facebook.com/plugins/page.php?href={href}&tabs=&width=340"
                       "&height=130&small_header=true&hide_cover=true&show_facepile=false",
        "ad_library_page": "https://www.facebook.com/ads/library/?active_status={status}&ad_type=all"
                           "&country={country}&media_type=all&view_all_page_id={page_id}",
        "ad_library_search": "https://www.facebook.com/ads/library/?active_status=all&ad_type=all"
                             "&country={country}&media_type=all&search_type=page&q={q}",
        "graphql": "https://www.facebook.com/api/graphql/",
        "fb_origin": "https://www.facebook.com",
        "ig_profile": "https://i.instagram.com/api/v1/users/web_profile_info/?username={username}",
        "fb_page": "https://www.facebook.com/{vanity}",
        "ig_page": "https://www.instagram.com/{username}/"},
    "ig_app_id": ["936619743392459"],
    "graphql_errors": {"1675004": "rate_limited", "1675002": "login_required"},
    "wayback": {"max_captures": 6, "collapse": "timestamp:6"},
    "generic_titles": ["facebook", "instagram", "log into facebook", "login • instagram"],
}
_REFS = load_ref(ref_path(__file__, "meta_transparency.json"), _FALLBACK)
_S = _REFS["settings"]
UA = _S.get("ua") or _FALLBACK["settings"]["ua"]
TIMEOUT = int(_S.get("timeout_seconds") or 30)
ATTEMPTS = max(1, int(_S.get("attempts") or 1))
BACKOFF = max(0.0, float(_S.get("backoff_seconds") or 0))
MAX_RETRY_AFTER = max(0.0, float(_S.get("max_retry_after_seconds") or 0))
COUNTRY = str(_S.get("country") or "ALL")
MAX_RELATED = int(_S.get("max_related_pages") or 20)
MAX_ADS = int(_S.get("max_ads_sampled") or 20)
EP = _REFS["endpoints"]
IG_APP_ID = (list(_REFS["ig_app_id"]) or _FALLBACK["ig_app_id"])[0]
GQL_ERRORS = {str(k): v for k, v in (_REFS["graphql_errors"] or {}).items()}
WB = _REFS["wayback"]
GENERIC_TITLES = {str(t).strip().lower() for t in _REFS["generic_titles"]}

CAVEAT = ("Every value here is an ACCOUNT-level fact — what Meta publishes about the account. "
          "A linked account, a confirmed owning organisation or an admin country is NOT the "
          "identity of the person who runs it; corroborate before any attribution.")
NO_COOKIES = ("Never request, accept or use cookies, session tokens, passwords or HAR files from "
              "the analyst — capture the panels below as screenshots instead.")

_VANITY_RE = re.compile(r"^[A-Za-z0-9_.\-]{2,80}$")
_FB_ROUTES = {"profile.php", "people", "pages", "pg", "share", "login", "story.php",
              "permalink.php", "watch", "reel", "groups"}


def _now():
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def _iso(epoch):
    try:
        return _dt.datetime.fromtimestamp(int(epoch), _dt.timezone.utc).date().isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def field(status, value=None, source=None, captured_at=None, note=None):
    out = {"status": status, "value": value, "source": source,
           "captured_at": captured_at or _now()}
    if note:
        out["note"] = note
    return out


# ---------------------------------------------------------------------------- HTTP seam
class Session:
    """One logged-out browser-like session: Android UA, in-memory jar for the anonymous edge
    challenge cookie only, Retry-After-aware retry. `request` never raises."""

    def __init__(self, timeout=None):
        self.timeout = timeout or TIMEOUT
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def _once(self, url, data, headers):
        h = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9",
             "Accept-Encoding": "gzip, deflate",
             "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.8"}
        if data is None:
            # a top-level navigation: the Ad Library answers 400 to a document GET without these
            h.update({"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
                      "Sec-Fetch-Site": "none", "Upgrade-Insecure-Requests": "1"})
        h.update(headers or {})
        req = urllib.request.Request(url, data=data, headers=h)
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                raw, hdrs, code = r.read(), dict(r.headers), r.status
        except urllib.error.HTTPError as e:
            try:
                raw = e.read()
            except Exception:  # noqa: BLE001
                raw = b""
            hdrs, code = dict(e.headers or {}), e.code
        except Exception as e:  # noqa: BLE001
            return None, {}, "", f"{type(e).__name__}: {e}"
        try:
            raw = _decode_body(raw, hdrs.get("Content-Encoding") or hdrs.get("content-encoding") or "")
        except Exception:  # noqa: BLE001
            pass
        return code, hdrs, raw.decode("utf-8", "replace"), None

    @staticmethod
    def _retry_after(hdrs):
        v = (hdrs.get("Retry-After") or hdrs.get("retry-after") or "").strip()
        if not v:
            return None
        if v.isdigit():
            return float(v)
        try:
            from email.utils import parsedate_to_datetime
            return max(0.0, (parsedate_to_datetime(v) - _dt.datetime.now(_dt.timezone.utc))
                       .total_seconds())
        except Exception:  # noqa: BLE001
            return None

    def request(self, url, data=None, headers=None, challenge=True):
        """→ (status, headers, text, err, retry_after). Retries 429/5xx; solves the anonymous
        edge challenge (`/__rd_verify…` POST) once when the page serves it."""
        retry_after = None
        for i in range(ATTEMPTS):
            code, hdrs, text, err = self._once(url, data, headers)
            if err is None and code == 403 and challenge and "__rd_verify" in text:
                m = re.search(r"fetch\('(/__rd_verify[^']+)'", text)
                if m:
                    self._once(EP["fb_origin"] + m.group(1), b"", {"Referer": url})
                    code, hdrs, text, err = self._once(url, data, headers)
            if err is None and code is not None and code != 429 and code < 500:
                return code, hdrs, text, None, None
            retry_after = self._retry_after(hdrs) if hdrs else None
            if i + 1 >= ATTEMPTS:
                break
            wait = retry_after if retry_after is not None else BACKOFF * (2 ** i)
            if wait > MAX_RETRY_AFTER:
                break
            time.sleep(wait)
        return code, hdrs, text, err, retry_after


def _status_of(code, err, text=""):
    if err:
        return "error"
    if code == 429:
        return "rate_limited"
    if code in (401,) or "require_login" in (text or "")[:500]:
        return "login_required"
    if code in (403, 400) or (code or 0) >= 500:
        return "blocked"
    return "error"


# ---------------------------------------------------------------------------- target parsing
def parse_target(raw, platform="auto"):
    """→ (platform, kind, value). kind ∈ id | vanity | username."""
    t = (raw or "").strip()
    if re.match(r"^https?://", t, re.I) or re.match(r"^(?:[a-z]+\.)?(facebook|instagram)\.com/", t, re.I):
        if not t.lower().startswith("http"):
            t = "https://" + t
        p = urllib.parse.urlsplit(t)
        host = (p.hostname or "").lower()
        segs = [s for s in p.path.split("/") if s]
        q = urllib.parse.parse_qs(p.query)
        if host.endswith("instagram.com"):
            return "instagram", "username", (segs[0] if segs else "")
        if q.get("id") and q["id"][0].isdigit():
            return "facebook", "id", q["id"][0]
        if q.get("view_all_page_id"):
            return "facebook", "id", q["view_all_page_id"][0]
        if segs and segs[0] in ("people", "pages", "pg") and segs[-1].isdigit():
            return "facebook", "id", segs[-1]
        if segs and segs[0] not in _FB_ROUTES:
            return "facebook", ("id" if segs[0].isdigit() else "vanity"), segs[0]
        return "facebook", "unresolved", t
    if platform == "instagram" or t.startswith("@") and platform != "facebook":
        return "instagram", "username", t.lstrip("@")
    if t.isdigit():
        return "facebook", "id", t
    return "facebook", "vanity", t.lstrip("@")


# ---------------------------------------------------------------------------- Facebook
def page_plugin(sess, ref):
    href = EP["fb_page"].format(vanity=urllib.parse.quote(ref, safe=""))
    url = EP["page_plugin"].format(href=urllib.parse.quote(href, safe=""))
    code, _h, text, err, ra = sess.request(url, challenge=False)
    at = _now()
    if err or code != 200:
        return {"status": _status_of(code, err, text), "retry_after": ra, "source": url,
                "captured_at": at}
    ids = re.findall(r"facebook\.com/(\d{5,})\?ref=embed_page", text)
    name = re.search(r'class="_1drp[^"]*" title="([^"]*)"', text) or \
        re.search(r'title="([^"]+)" href="https://www\.facebook\.com/\d+\?ref=embed_page"', text)
    foll = re.search(r">([\d.,]+[KMB]?) followers<", text)
    if not ids:
        return {"status": "not_exposed", "source": url, "captured_at": at,
                "note": "the Page plugin rendered no Page — a personal profile, a restricted or "
                        "removed Page, or a vanity that does not exist"}
    return {"status": "found", "page_id": ids[0], "source": url, "captured_at": at,
            "name": html.unescape(name.group(1)) if name else None,
            "followers": foll.group(1) if foll else None}


def _find_all(obj, key):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key:
                yield v
            yield from _find_all(v, key)
    elif isinstance(obj, list):
        for v in obj:
            yield from _find_all(v, key)


def _preloader(text):
    m = re.search(r'"queryID":"(\d+)","variables":', text)
    if not m:
        return None, None
    try:
        variables, _ = json.JSONDecoder().raw_decode(text, m.end())
    except ValueError:
        return m.group(1), None
    return m.group(1), variables


def _graphql_chunks(text):
    chunks = []
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("for (;;);"):
            line = line[len("for (;;);"):]
        if not line:
            continue
        try:
            chunks.append(json.loads(line))
        except ValueError:
            continue
    return chunks


def ad_library(sess, page_id):
    """Ad Library page view + its About tab. → dict with `status`, `surfaces`, raw blocks."""
    out = {"surfaces": {}}
    page_url = EP["ad_library_page"].format(status="active", country=COUNTRY, page_id=page_id)
    code, _h, text, err, ra = sess.request(page_url)
    out["page_url"], out["page_at"] = page_url, _now()
    if err or code != 200:
        out["status"] = _status_of(code, err, text)
        out["retry_after"] = ra
        out["surfaces"]["ad_library_page"] = out["status"]
        return out
    out["surfaces"]["ad_library_page"] = "found"
    m = re.search(r'"search_results_connection":\{"count":(\d+)', text)
    out["ads_active"] = int(m.group(1)) if m else None
    lsd = re.search(r'"LSD",\[\],\{"token":"([^"]+)"', text)
    doc_id, variables = _preloader(text)
    if not (lsd and doc_id and isinstance(variables, dict)):
        out["status"] = "blocked"
        out["surfaces"]["ad_library_about"] = "blocked"
        out["note"] = "the Ad Library page carried no LSD token / root-query preloader (markup change)"
        return out
    variables = dict(variables, isAboutTab=True, activeStatus="all",
                     fetchPageInfo=True, fetchSharedDisclaimers=True, viewAllPageID=str(page_id))
    body = urllib.parse.urlencode({
        "av": "0", "__user": "0", "__a": "1", "lsd": lsd.group(1),
        "fb_api_caller_class": "RelayModern",
        "fb_api_req_friendly_name": "AdLibraryFoundationRootQuery",
        "variables": json.dumps(variables), "server_timestamps": "true", "doc_id": doc_id}).encode()
    hdrs = {"X-FB-LSD": lsd.group(1), "X-FB-Friendly-Name": "AdLibraryFoundationRootQuery",
            "Content-Type": "application/x-www-form-urlencoded", "Origin": EP["fb_origin"],
            "Referer": page_url, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty", "Accept": "*/*"}
    status, chunks = "error", []
    for i in range(ATTEMPTS):
        code, _h, gtext, err, ra = sess.request(EP["graphql"], data=body, headers=hdrs)
        out["about_at"] = _now()
        if err or code != 200:
            status = _status_of(code, err, gtext)
            break
        chunks = _graphql_chunks(gtext)
        codes = [str(e.get("code")) for c in chunks for e in (c.get("errors") or [])]
        mapped = [GQL_ERRORS.get(c) for c in codes if GQL_ERRORS.get(c)]
        if "rate_limited" in mapped and i + 1 < ATTEMPTS and BACKOFF * (2 ** i) <= MAX_RETRY_AFTER:
            time.sleep(BACKOFF * (2 ** i))
            continue
        status = mapped[0] if mapped and not any(c.get("data") for c in chunks) else "found"
        if codes:
            out["graphql_errors"] = codes
        break
    out["status"] = status
    out["surfaces"]["ad_library_about"] = status
    out["about_source"] = f"{EP['graphql']} (AdLibraryFoundationRootQuery, isAboutTab, page {page_id})"
    out["chunks"] = [c.get("data") for c in chunks if isinstance(c.get("data"), dict)]
    return out


def _merge_page_info(chunks):
    merged = {}
    for d in chunks:
        for alpi in _find_all(d, "ad_library_page_info"):
            if isinstance(alpi, dict):
                for k, v in (alpi.get("page_info") or {}).items():
                    if v not in (None, [], "") and k not in merged:
                        merged[k] = v
                if alpi.get("page_spend") is not None:
                    merged.setdefault("page_spend", alpi.get("page_spend"))
    return merged


def _page_block(chunks, page_id):
    best = {}
    for d in chunks:
        for p in _find_all(d, "page"):
            if isinstance(p, dict) and str(p.get("id")) == str(page_id):
                for k, v in p.items():
                    if k not in best or best[k] in (None, {}, []):
                        best[k] = v
    return best


def _ad_name_history(chunks, page_id):
    names, ads, contacts = {}, [], []
    for d in chunks:
        for res in _find_all(d, "collated_results"):
            for ad in res if isinstance(res, list) else ():
                if str(ad.get("page_id")) != str(page_id):
                    continue
                snap = ad.get("snapshot") or {}
                nm = snap.get("page_name")
                start, end = ad.get("start_date"), ad.get("end_date")
                if nm:
                    rec = names.setdefault(nm, {"first": None, "last": None, "ads": 0})
                    rec["ads"] += 1
                    for t in (start, end):
                        if isinstance(t, int):
                            rec["first"] = t if rec["first"] is None else min(rec["first"], t)
                            rec["last"] = t if rec["last"] is None else max(rec["last"], t)
                if len(ads) < MAX_ADS:
                    ads.append({"ad_archive_id": ad.get("ad_archive_id"), "page_name": nm,
                                "is_active": ad.get("is_active"), "start": _iso(start),
                                "end": _iso(end), "byline": snap.get("byline")})
                fev = ad.get("fev_info")
                if isinstance(fev, dict):
                    c = {k: fev.get(k) for k in ("submitted_on", "phone", "email", "website",
                                                 "address") if fev.get(k)}
                    if c and c not in contacts:
                        contacts.append(c)
    hist = [{"value": n, "first_seen": _iso(r["first"]), "last_seen": _iso(r["last"]),
             "ads": r["ads"]} for n, r in names.items()]
    hist.sort(key=lambda h: h["first_seen"] or "")
    return hist, ads, contacts


def facebook(sess, kind, value):
    res = {"platform": "facebook", "fields": {}, "surfaces": {}, "history": {}, "handles": [],
           "emails": [], "phones": [], "linked_accounts": []}
    F = res["fields"]
    page_id = value if kind == "id" else None
    vanity = value if kind == "vanity" else None
    plug = page_plugin(sess, value) if kind in ("id", "vanity") else {"status": "error"}
    res["surfaces"]["page_plugin"] = plug["status"]
    if plug["status"] == "found":
        page_id = plug["page_id"]
        F["page_name"] = field("found", plug.get("name"), plug["source"], plug["captured_at"])
        F["followers"] = field("found", plug.get("followers"), plug["source"], plug["captured_at"])
    F["page_id"] = (field("found", page_id, plug.get("source"), plug.get("captured_at"))
                    if page_id else
                    field(plug["status"], None, plug.get("source"), plug.get("captured_at"),
                          plug.get("note")))
    if vanity:
        res["handles"].append({"platform": "facebook", "value": vanity, "kind": "username",
                               "source": "input"})
    if page_id:
        res["handles"].append({"platform": "facebook", "value": page_id, "kind": "page_id",
                               "source": plug.get("source") or "input"})
    al = ad_library(sess, page_id) if page_id else {"status": "not_exposed", "surfaces": {}}
    res["surfaces"].update(al.get("surfaces") or {})
    st, src, at = al.get("status"), al.get("about_source"), al.get("about_at")
    chunks = al.get("chunks") or []
    pi = _merge_page_info(chunks)
    pb = _page_block(chunks, page_id) if page_id else {}
    pti = pb.get("pages_transparency_info") or {}
    absent = "not_exposed" if st == "found" else (st or "not_exposed")

    def put(name, val, note=None):
        F[name] = field("found", val, src, at, note) if val not in (None, [], {}, "") else \
            field(absent, None, src, at, note if st == "found" else al.get("note"))

    if pb.get("name") or pi.get("page_name"):
        F["page_name"] = field("found", pb.get("name") or pi.get("page_name"), src, at)
    put("vanity", pi.get("page_alias"))
    put("category", pi.get("page_category"))
    put("about", (pb.get("about") or {}).get("text") if isinstance(pb.get("about"), dict) else None)
    put("likes", pi.get("likes"))
    put("entity_type", pi.get("entity_type"))
    put("verification", pi.get("page_verification"))
    put("page_is_deleted", pi.get("page_is_deleted") if "page_is_deleted" in pi else None)
    items = pti.get("history_items") or []
    created = [_iso(h.get("event_time")) for h in items if h.get("item_type") == "CREATION"]
    put("creation_date", created[0] if created else None)
    put("name_changes", [_iso(h.get("event_time")) for h in items
                         if h.get("item_type") == "NAME_CHANGE"] or None,
        "dates only — the Ad Library About tab does not show the previous names; see "
        "history.name and the capture checklist")
    put("page_history_events", [{"type": h.get("item_type"), "date": _iso(h.get("event_time"))}
                                for h in items] or None)
    put("state_media_label", pti.get("state_media_country_label"))
    admins = ((pti.get("admin_locations") or {}).get("admin_country_counts") or [])
    put("admin_countries", [{"country": (a.get("country") or {}).get("iso_name"),
                             "count": a.get("count")} for a in admins] or None,
        "countries of the people who manage the Page — account-level, not identities")
    owner = pb.get("confirmed_page_owner")
    put("confirmed_owner_org", {"name": owner.get("name"), "id": owner.get("id"),
                                "information": owner.get("information")}
        if isinstance(owner, dict) else None,
        "organisation Meta confirmed as managing the Page — not a person attribution")
    ig = {"username": pi.get("ig_username"), "followers": pi.get("ig_followers"),
          "verified": pi.get("ig_verification")} if pi.get("ig_username") else None
    put("linked_instagram", ig)
    if ig:
        res["handles"].append({"platform": "instagram", "value": ig["username"],
                               "kind": "username", "source": "ad_library.pages_and_accounts"})
        res["linked_accounts"].append({"platform": "instagram", "value": ig["username"],
                                       "relation": "linked to the Page (Ad Library)"})
    ads_total = None
    for d in chunks:
        for conn in _find_all(d, "search_results_connection"):
            if isinstance(conn, dict) and isinstance(conn.get("count"), int):
                ads_total = conn["count"]
    put("ads_total", ads_total)
    F["ads_active"] = (field("found", al.get("ads_active"), al.get("page_url"), al.get("page_at"))
                       if al.get("ads_active") is not None else
                       field(al.get("surfaces", {}).get("ad_library_page", absent), None,
                             al.get("page_url"), al.get("page_at")))
    shared = []
    for d in chunks:
        for sdi in _find_all(d, "shared_disclaimer_pages"):
            for sp in sdi or ():
                shared.append({"page_id": sp.get("page_id"),
                               "page_name": (sp.get("page_info") or {}).get("page_name"),
                               "category": (sp.get("page_info") or {}).get("page_category")})
    put("shared_disclaimer_pages", shared or None,
        "Pages that ran ads under the same paid-for-by disclaimer")
    related = [{"page_id": r.get("page_id"), "page_name": r.get("page_name"),
                "country": r.get("country"), "category": r.get("category_name")}
               for r in (pi.get("related_pages") or [])][:MAX_RELATED]
    put("related_pages", related or None, "Pages the Ad Library groups with this one")
    put("page_spend", pi.get("page_spend") if any(
        (pi.get("page_spend") or {}).get(k) for k in ("current_week", "lifetime_by_disclaimer",
                                                      "weekly_by_disclaimer")) else None)
    hist, ads, contacts = _ad_name_history(chunks, page_id) if page_id else ([], [], [])
    put("ad_disclaimer_contacts", contacts or None,
        "advertiser-declared paid-for-by contact details on the Page's ads")
    for c in contacts:
        if c.get("email"):
            res["emails"].append(c["email"])
        if c.get("phone"):
            res["phones"].append(c["phone"])
    put("ads_sampled", ads or None)
    if hist:
        res["history"]["name"] = [dict(h, source="ad_library.ad_snapshots.page_name") for h in hist]
    F["business_contact"] = field(
        "login_required", None, EP["fb_page"].format(vanity=vanity or page_id or ""), _now(),
        "Page contact info (email / phone / website / address) is not served logged-out; see "
        "the capture checklist")
    res["page_id"], res["vanity"] = page_id, vanity or pi.get("page_alias")
    return res


def search_pages(sess, name):
    url = EP["ad_library_search"].format(country=COUNTRY, q=urllib.parse.quote(name))
    code, _h, text, err, ra = sess.request(url)
    at = _now()
    if err or code != 200:
        return {"status": _status_of(code, err, text), "retry_after": ra, "source": url,
                "captured_at": at, "candidates": []}
    seen = {}
    for m in re.finditer(r'"page_id":"(\d+)","page_is_deleted":(true|false),"snapshot":\{[^{}]*?'
                         r'"page_name":"((?:[^"\\]|\\.)*)"', text):
        nm = json.loads('"' + m.group(3) + '"')
        rec = seen.setdefault(m.group(1), {"page_id": m.group(1), "names": [], "ads_seen": 0,
                                           "deleted": m.group(2) == "true"})
        rec["ads_seen"] += 1
        if nm not in rec["names"]:
            rec["names"].append(nm)
    return {"status": "found" if seen else "not_exposed", "source": url, "captured_at": at,
            "candidates": sorted(seen.values(), key=lambda r: -r["ads_seen"]),
            "note": "Ad Library page-name search: candidates are Pages whose ads match the name "
                    "(the logged-out GraphQL typeahead answers 'Unauthorized logged out query'); "
                    "a Page that never advertised will not appear"}


# ---------------------------------------------------------------------------- Instagram
def instagram(sess, username):
    res = {"platform": "instagram", "fields": {}, "surfaces": {}, "history": {},
           "handles": [{"platform": "instagram", "value": username, "kind": "username",
                        "source": "input"}],
           "emails": [], "phones": [], "linked_accounts": []}
    F = res["fields"]
    url = EP["ig_profile"].format(username=urllib.parse.quote(username))
    code, _h, text, err, ra = sess.request(url, headers={
        "X-IG-App-ID": IG_APP_ID, "Accept": "*/*", "X-Requested-With": "XMLHttpRequest",
        "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-site",
        "Referer": EP["ig_page"].format(username=username)}, challenge=False)
    at = _now()
    user = None
    if not err and code == 200:
        try:
            user = (json.loads(text).get("data") or {}).get("user")
        except ValueError:
            user = None
    if user:
        status = "found"
    elif not err and code in (200, 404):
        status = "not_exposed"
    else:
        status = _status_of(code, err, text)
    res["surfaces"]["ig_web_profile"] = status
    if ra is not None:
        res["surfaces"]["ig_web_profile_retry_after"] = ra
    u = user or {}
    absent = "not_exposed" if status == "found" else status

    def put(name, val, note=None):
        F[name] = field("found", val, url, at, note) if val not in (None, [], {}, "") else \
            field(absent, None, url, at, note)

    put("user_id", u.get("id"))
    put("full_name", u.get("full_name"))
    put("biography", u.get("biography"))
    put("external_url", u.get("external_url"))
    put("bio_links", [b.get("url") for b in (u.get("bio_links") or []) if b.get("url")] or None)
    put("category", u.get("category_name") or u.get("business_category_name"))
    put("is_business", u.get("is_business_account") if user else None)
    put("is_professional", u.get("is_professional_account") if user else None)
    put("is_verified", u.get("is_verified") if user else None)
    put("is_private", u.get("is_private") if user else None)
    put("business_email", u.get("business_email"))
    put("business_phone", u.get("business_phone_number"))
    addr = u.get("business_address_json")
    if isinstance(addr, str):
        try:
            addr = json.loads(addr)
        except ValueError:
            pass
    put("business_address", addr or None)
    put("linked_fb_id", u.get("fbid"),
        "Facebook account id Meta links to this IG account — account-level link only")
    put("counts", {"followers": (u.get("edge_followed_by") or {}).get("count"),
                   "following": (u.get("edge_follow") or {}).get("count"),
                   "posts": (u.get("edge_owner_to_timeline_media") or {}).get("count")}
        if user else None)
    if user and not (u.get("business_email") or u.get("business_phone_number")):
        F["business_email"]["note"] = F["business_phone"]["note"] = \
            "not published on the public profile (or only behind the logged-in Contact button)"
    for k in ("about_this_account_date_joined", "about_this_account_country",
              "former_usernames"):
        F[k] = field("login_required", None, EP["ig_page"].format(username=username), at,
                     "'About this account' is served only to logged-in viewers")
    if u.get("business_email"):
        res["emails"].append(u["business_email"])
    if u.get("business_phone_number"):
        res["phones"].append(u["business_phone_number"])
    if u.get("fbid"):
        res["linked_accounts"].append({"platform": "facebook", "value": u["fbid"],
                                       "relation": "fbid on the IG profile"})
        res["handles"].append({"platform": "facebook", "value": u["fbid"], "kind": "profile_id",
                               "source": "ig_web_profile.fbid"})
    return res


# ---------------------------------------------------------------------------- Wayback history
def _meta(text, prop):
    m = re.search(r'<meta[^>]+(?:property|name)="%s"[^>]+content="([^"]*)"' % re.escape(prop), text) \
        or re.search(r'<meta[^>]+content="([^"]*)"[^>]+(?:property|name)="%s"' % re.escape(prop), text)
    return html.unescape(m.group(1)).strip() if m else None


def _json_str(text, key):
    m = re.search(r'"%s":"((?:[^"\\]|\\.){1,600})"' % re.escape(key), text)
    if not m:
        return None
    try:
        return json.loads('"' + m.group(1) + '"').strip() or None
    except ValueError:
        return None


def extract_capture(text, platform, handle=None):
    """Account fields from one archived profile page (best-effort, markup varies by era)."""
    out = {}
    title = re.search(r"<title[^>]*>([^<]{1,300})</title>", text, re.I)
    t = html.unescape(title.group(1)).strip() if title else ""
    og = _meta(text, "og:title") or ""
    for cand in (og, t):
        c = re.sub(r"\s*[|\-–•]\s*(Facebook|Instagram.*)$", "", cand).strip()
        c = re.sub(r"\s*-\s*Home$", "", c).strip()
        if platform == "instagram":
            # only a "Name (@handle)" title for THIS handle names the profile; older eras titled
            # the page after a feed item or "<x> on Instagram", which is not the account's name
            m = re.match(r"^(.*?)\s*\(@([A-Za-z0-9_.]+)\)", c)
            if m and (not handle or m.group(2).lower() == handle.lower()):
                out.setdefault("name", m.group(1).strip() or None)
            continue
        if c and c.lower() not in GENERIC_TITLES and cand.lower() not in GENERIC_TITLES:
            out.setdefault("name", c)
    # JSON keys are read only from Instagram's profile payload, and only from the window around
    # the profile's OWN user object ("username":"<handle>") — older pages embed feed/comment users
    # whose names and bios would otherwise pollute the history. On a Facebook page the same keys
    # belong to posts / link previews, so only category is read there.
    scope = ""
    if platform == "instagram" and handle:
        m = re.search(r'"username":"%s"' % re.escape(handle), text, re.I)
        scope = text[max(0, m.start() - 4000):m.end() + 4000] if m else ""
    keys = ((("full_name", "name"), ("biography", "bio"), ("external_url", "external_url"),
             ("category_name", "category")) if platform == "instagram"
            else (("category_name", "category"),))
    for key, fld in keys:
        v = _json_str(scope if platform == "instagram" else text, key)
        if v and fld not in out:
            out[fld] = v
    v = _json_str(text, "addressLocality")
    if v:
        out.setdefault("location", v)
    desc = _meta(text, "og:description") or _meta(text, "description")
    if desc and "bio" not in out and platform == "facebook":
        # drop the volatile counter prefix ("Name. 1,234 likes · 56 talking about this.")
        desc = re.sub(r"^.{0,120}?[\d.,]+[KMB]?\s+(?:likes|followers)\b[^.]*\.\s*", "", desc)
        desc = re.sub(r"[\d.,]+[KMB]?\s+(?:likes|followers|talking about this|were here)"
                      r"\s*[·.]?\s*", "", desc).strip(" ·.")
        if desc and desc.lower() not in GENERIC_TITLES and \
                not desc.lower().startswith("see posts, photos and more on facebook"):
            out["bio"] = desc
    loc = _meta(text, "og:locality") or _meta(text, "place:location:locality")
    if loc:
        out.setdefault("location", loc)
    return {k: v for k, v in out.items() if v}


def wayback_history(page_url, platform, handle=None):
    import wp_wayback as wb
    import wp_wayback_guard as wg
    reason = wg.blocked()
    if reason:
        return {"status": "skipped", "note": f"Wayback breaker tripped: {reason}"}, {}
    rows, err = wb.index([("url", wb._index_key(page_url)), ("fl", "timestamp,original"),
                          ("filter", "statuscode:200"), ("collapse", WB.get("collapse") or
                                                         "timestamp:6")])
    if rows is None:
        return {"status": "error", "note": f"Wayback index did not answer: {err}"}, {}
    rows = [r for r in rows if len(r) >= 2]
    meta = {"status": "found" if rows else "not_exposed", "captures_indexed": len(rows),
            "source": f"web.archive.org CDX url={wb._index_key(page_url)}",
            "caveat": "captures are keyed on the handle URL: a capture shows whoever held the "
                      "handle at that time, so an abrupt name/bio change can be a different "
                      "account reusing the handle, not a rename"}
    if not rows:
        meta["note"] = "no 200 captures of the profile URL in the Wayback index"
        return meta, {}
    n = max(1, int(WB.get("max_captures") or 6))
    pick = rows if len(rows) <= n else [rows[round(i * (len(rows) - 1) / (n - 1))]
                                        for i in range(n)] if n > 1 else [rows[-1]]
    captures, fails, limit = [], 0, wg.fail_limit()
    for ts, orig in ((r[0], r[1]) for r in pick):
        if wg.blocked():
            meta["note"] = "Wayback breaker tripped mid-run — remaining captures not fetched"
            break
        resp, used, ferr = wb.fetch_capture(ts, orig)
        if resp is None:
            fails += 1
            captures.append({"timestamp": used, "error": ferr})
            if fails > limit:
                meta["note"] = f"stopped after {fails} consecutive capture failures"
                break
            continue
        fails = 0
        fields = extract_capture(resp.body.decode("utf-8", "replace"), platform, handle)
        captures.append({"timestamp": used, "snapshot": wb.snapshot_url(used, orig),
                         "fields": fields})
    meta["captures_fetched"] = sum(1 for c in captures if "fields" in c)
    meta["captures"] = captures
    hist = {}
    for c in sorted((c for c in captures if c.get("fields")), key=lambda c: c["timestamp"]):
        day = f"{c['timestamp'][:4]}-{c['timestamp'][4:6]}-{c['timestamp'][6:8]}"
        for k, v in c["fields"].items():
            runs = hist.setdefault(k, [])
            if runs and runs[-1]["value"] == v:
                runs[-1]["last_seen"] = day
            else:
                runs.append({"value": v, "first_seen": day, "last_seen": day,
                             "source": c["snapshot"]})
    return meta, hist


# ---------------------------------------------------------------------------- checklist
def capture_checklist(res):
    F, plat, items = res.get("fields") or {}, res.get("platform"), []

    def missing(*names):
        return [n for n in names if (F.get(n) or {}).get("status") != "found"]

    if plat == "facebook":
        m = missing("creation_date", "admin_countries", "page_history_events")
        items.append({"panel": "Facebook Page → About → Page transparency → See all",
                      "why": "creation date, EVERY previous Page name with its change date, "
                             "countries of the people who manage the Page, ads running",
                      "fields": m + ["name_changes (previous names)"], "needed": True})
        m = missing("confirmed_owner_org", "linked_instagram", "ads_total")
        items.append({"panel": "Ad Library → search the Page → open it → About tab "
                               "(Page history, People who manage this Page, Organisations that "
                               "manage this Page, Pages and accounts)",
                      "why": "confirms the transparency block when the keyless call was "
                             "blocked or rate-limited", "fields": m, "needed": bool(m)})
        items.append({"panel": "Facebook Page (or profile) → About → Contact info / Basic info "
                               "/ Places lived / Details (Other names)",
                      "why": "business contact email, phone, website, address; profile "
                             "locations and other names (not served logged-out)",
                      "fields": ["business_contact", "locations"], "needed": True})
    if plat == "instagram":
        items.append({"panel": "Instagram profile → ⋯ menu → About this account",
                      "why": "date joined, account based in (country), FORMER USERNAMES with "
                             "dates, verification, ads",
                      "fields": ["about_this_account_date_joined", "about_this_account_country",
                                 "former_usernames"], "needed": True})
        m = missing("full_name", "biography", "business_email", "business_phone")
        items.append({"panel": "Instagram profile header + Contact button",
                      "why": "name, bio, links, category and the business email/phone shown "
                             "behind Contact", "fields": m, "needed": bool(m)})
    for it in items:
        it["how"] = ("full-window screenshot with the address bar and system clock visible, "
                     "while logged in with the analyst's own research account; import via "
                     "evidence_import with the capture time")
    return items


# ---------------------------------------------------------------------------- driver
def _case_dir(case_id):
    home = os.environ.get("INTEL_HOME") or ENGINE
    return os.path.join(home, "cases", case_id)


def collect(target, platform="auto", wayback=True, follow_linked=True, timeout=None):
    sess = Session(timeout)
    plat, kind, value = parse_target(target, platform)
    if kind == "unresolved" or not value:
        return {"tool": "meta_transparency", "target": target, "platform": plat,
                "error": "could not read a Page id, vanity or username from the target — "
                         "run sharelink_resolve on share links first"}
    res = facebook(sess, kind, value) if plat == "facebook" else instagram(sess, value)
    if plat == "facebook" and follow_linked:
        ig = (res["fields"].get("linked_instagram") or {}).get("value")
        if ig and ig.get("username"):
            sub = instagram(sess, ig["username"])
            res["linked_instagram_profile"] = {k: sub[k] for k in ("fields", "surfaces")}
            res["emails"] += [e for e in sub["emails"] if e not in res["emails"]]
            res["phones"] += [p for p in sub["phones"] if p not in res["phones"]]
    if wayback:
        if plat == "facebook":
            key = res.get("vanity") or res.get("page_id") or value
            page_url = EP["fb_page"].format(vanity=key)
        else:
            page_url = EP["ig_page"].format(username=value)
        meta, hist = wayback_history(page_url, plat, None if plat == "facebook" else value)
        res["surfaces"]["wayback"] = meta.get("status")
        res["wayback"] = meta
        for k, runs in hist.items():
            res["history"][k] = sorted(res["history"].get(k, []) + runs,
                                       key=lambda r: r.get("first_seen") or "")
    else:
        res["surfaces"]["wayback"] = "skipped"
    res["capture_checklist"] = capture_checklist(res)
    res.update({"tool": "meta_transparency", "target": target, "collected_at": _now(),
                "caveat": CAVEAT, "analyst_rule": NO_COOKIES})
    return res


def _slug(s):
    return re.sub(r"[^A-Za-z0-9_.\-]+", "_", str(s or "target"))[:80].strip("_") or "target"


def write_case(case_id, res):
    cdir = _case_dir(case_id)
    if not os.path.isdir(cdir):
        return None, f"case dir not found: {cdir} (open the case first; nothing written)"
    out_dir = os.path.join(cdir, "enrichment", "meta_transparency")
    os.makedirs(out_dir, exist_ok=True)
    key = res.get("vanity") or res.get("page_id") or res.get("target")
    path = os.path.join(out_dir, f"{res.get('platform', 'meta')}_{_slug(key)}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=2, ensure_ascii=False)
    return path, None


def _summary(res):
    F = res.get("fields") or {}
    lines = [f"[meta] {res.get('platform')} {res.get('target')} — surfaces: "
             + ", ".join(f"{k}={v}" for k, v in (res.get("surfaces") or {}).items())]
    for k, v in F.items():
        val = v.get("value")
        s = json.dumps(val, ensure_ascii=False) if val is not None else ""
        lines.append(f"  {k:<28} {v['status']:<15} {s[:100]}")
    for k, runs in (res.get("history") or {}).items():
        lines.append(f"  history.{k}: " + " → ".join(f"{r['value'][:40] if isinstance(r['value'], str) else r['value']}"
                                                     f" ({r.get('first_seen')}..{r.get('last_seen')})"
                                                     for r in runs[:6]))
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Keyless Meta (Facebook Page / Instagram) account "
                                             "transparency + name/bio history.")
    ap.add_argument("target", nargs="?", help="FB vanity / numeric id / URL, or IG @handle / URL")
    ap.add_argument("--platform", choices=["auto", "facebook", "instagram"], default="auto")
    ap.add_argument("--search", help="Ad Library page-name search instead of a target")
    ap.add_argument("--case", help="case id — write cases/<id>/enrichment/meta_transparency/…")
    ap.add_argument("--no-wayback", action="store_true", help="skip the Wayback history pass")
    ap.add_argument("--no-linked", action="store_true",
                    help="do not follow the Page's linked Instagram account")
    ap.add_argument("--timeout", type=int)
    ap.add_argument("--json", action="store_true", help="compact JSON on stdout")
    a = ap.parse_args()
    if a.case:
        os.environ.setdefault("WP_CASE_DIR", _case_dir(a.case))
    if a.search:
        res = dict(search_pages(Session(a.timeout), a.search), tool="meta_transparency",
                   platform="search", target=a.search, caveat=CAVEAT)
    elif a.target:
        res = collect(a.target, a.platform, wayback=not a.no_wayback,
                      follow_linked=not a.no_linked, timeout=a.timeout)
        print(_summary(res), file=sys.stderr)
    else:
        ap.error("a target or --search is required")
    if a.case:
        path, err = write_case(a.case, res)
        res["written_to"] = path
        if err:
            res["write_error"] = err
            print(f"[meta] {err}", file=sys.stderr)
    print(json.dumps(res, indent=None if a.json else 2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
