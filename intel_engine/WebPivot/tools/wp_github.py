"""wp_github — GitHub committer-identity harvest for a user, organisation, repository or commit.

The one thing GitHub never redacts is the `From:` line of a commit patch. `<commit-url>.patch`
is a plain-text mbox whose first block carries the author's configured name and e-mail exactly as
git recorded them — a personal mailbox, a company address, or GitHub's no-reply form
`<user-id>+<login>@users.noreply.github.com`, which itself binds a numeric user id to a login.
This module walks a target's public repositories, samples their commit history and harvests
those identities, plus the profile-level selectors (blog, Twitter, company, location, public
e-mail) for a user or organisation and its top contributors.

Sampling rule (keeps the walk cheap and unbiased across a long history): a repository with more
than `SAMPLE_THRESHOLD` (10) commits contributes its FIRST 2 and LAST 2 commits — the first commits
are the founder's, the last the current maintainer's; a repository at or under the threshold
contributes every commit.

Keyless. api.github.com allows 60 unauthenticated requests/hour per IP; a GITHUB_TOKEN raises the
limit to 5000 and is sent as `Authorization: Bearer` when present. Every request goes through
`wp_net.fetch`, so the CTI egress-proxy pool applies. GitHub is never the hostile target here.

Output: a dict with `target`, `kind`, `profile`, `repos[]` (each with `commits_sampled[]`),
`contributors[]` (org / repo), `identities[]` (deduplicated {name, email, login, user_id, kind,
first_seen, last_seen, repos[]}) and `pivots[]` in the pivot_extract shape, so `kb_ingest` and the
frontier treat a harvested e-mail exactly like one scraped from a web page.

Attribution rails: a commit e-mail is the COMMITTER's identity, not the repository owner's — a
fork, a merged pull request or a bot commit carries someone else's address. Every identity row
names the login the API attributed it to (or none), and the `kind` field separates `personal`,
`noreply`, `bot` and `org-domain` so the analyst never clusters on a `github-actions[bot]` line.
"""
import os
import re
import sys
import json
import time
import argparse
import urllib.parse
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from wp_net import fetch, DEFAULT_UA  # noqa: E402
try:
    import api_usage  # noqa: E402
except Exception:  # pragma: no cover
    api_usage = None

API = "https://api.github.com"
WEB = "https://github.com"
SAMPLE_THRESHOLD = 10          # > this many commits -> first 2 + last 2
SAMPLE_EDGE = 2
MAX_REPOS_DEFAULT = 30
MAX_CONTRIBUTORS_DEFAULT = 10
PER_PAGE = 100

_NOREPLY = re.compile(r"^(?:(\d+)\+)?([A-Za-z0-9-]+)@users\.noreply\.github\.com$", re.I)
_BOT = re.compile(r"\[bot\]$|^(dependabot|renovate|github-actions|greenkeeper|snyk-bot|imgbot)", re.I)
_PATCH_FROM = re.compile(r"^From:\s*(.*?)\s*<([^>]+)>\s*$", re.M)
_PATCH_DATE = re.compile(r"^Date:\s*(.+?)\s*$", re.M)
_PATCH_SUBJ = re.compile(r"^Subject:\s*(.+?)\s*$", re.M)
_SOCIAL_HOSTS = ("twitter.com", "x.com", "facebook.com", "fb.com", "t.me", "telegram.me", "zalo.me",
                 "linkedin.com", "instagram.com", "youtube.com", "tiktok.com", "discord.gg",
                 "discord.com", "mastodon.social", "bsky.app", "keybase.io", "medium.com", "dev.to")


# ------------------------------------------------------------------ HTTP
def _token():
    for k in ("GITHUB_TOKEN", "GH_TOKEN", "GITHUB_PAT"):
        v = os.environ.get(k, "").strip()
        if v:
            return v
    return None


def _headers(token=None, accept="application/vnd.github+json"):
    h = {"User-Agent": DEFAULT_UA, "Accept": accept, "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


class _Http:
    """Small GET wrapper: JSON or text, remembers the rate-limit state, never raises."""

    def __init__(self, token=None, timeout=25, sleep=0.0):
        self.token = token
        self.timeout = timeout
        self.sleep = sleep
        self.calls = 0
        self.remaining = None
        self.errors = []

    def _get(self, url, accept):
        self.calls += 1
        if self.sleep:
            time.sleep(self.sleep)
        try:
            _, status, headers, body = fetch(url, timeout=self.timeout, ua=DEFAULT_UA,
                                             extra_headers=_headers(self.token, accept))
        except Exception as e:  # noqa: BLE001
            self.errors.append(f"{url}: {e}")
            return None, None
        hl = {k.lower(): v for k, v in (headers or {}).items()}
        if "x-ratelimit-remaining" in hl:
            try:
                self.remaining = int(hl["x-ratelimit-remaining"])
            except ValueError:
                pass
        if status == 403 and self.remaining == 0:
            self.errors.append("rate-limited by api.github.com (set GITHUB_TOKEN for 5000/h)")
        if status and status >= 400:
            return status, None
        return status, body

    def json(self, path, params=None):
        url = path if path.startswith("http") else API + path
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        status, body = self._get(url, "application/vnd.github+json")
        if body is None:
            return None
        try:
            return json.loads(body.decode("utf-8", "ignore"))
        except ValueError:
            return None

    def text(self, url):
        status, body = self._get(url, "text/plain")
        return body.decode("utf-8", "ignore") if body else None


# ------------------------------------------------------------------ target parsing
def parse_target(target: str) -> dict:
    """'cmsnt' | 'org/repo' | github.com/<owner> | .../<owner>/<repo> | .../commit/<sha> -> kind+parts."""
    t = (target or "").strip()
    if not t:
        raise ValueError("empty target")
    if "github.com" in t:
        p = urlparse(t if "://" in t else "https://" + t)
        parts = [x for x in p.path.split("/") if x]
    else:
        parts = [x for x in t.split("/") if x]
    if not parts:
        raise ValueError(f"no owner in target: {target}")
    owner = parts[0]
    if len(parts) >= 4 and parts[2] in ("commit", "commits"):
        return {"kind": "commit", "owner": owner, "repo": parts[1], "sha": parts[3].split(".")[0]}
    if len(parts) >= 2 and parts[1] not in ("orgs", "users"):
        return {"kind": "repo", "owner": owner, "repo": parts[1]}
    if owner in ("orgs", "users") and len(parts) >= 2:
        return {"kind": "owner", "owner": parts[1]}
    return {"kind": "owner", "owner": owner}


# ------------------------------------------------------------------ identity model
def classify_email(email: str, name: str = "") -> dict:
    """{kind, login, user_id} for a commit e-mail — the join-key semantics the analyst needs."""
    e = (email or "").strip()
    m = _NOREPLY.match(e)
    if m:
        return {"kind": "noreply", "login": m.group(2), "user_id": int(m.group(1)) if m.group(1) else None}
    if _BOT.search(name or "") or _BOT.search(e.split("@")[0]):
        return {"kind": "bot", "login": None, "user_id": None}
    dom = e.rsplit("@", 1)[-1].lower() if "@" in e else ""
    from_free = dom in ("gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
                        "icloud.com", "proton.me", "protonmail.com", "qq.com", "163.com", "mail.ru")
    return {"kind": "personal" if from_free or not dom else "org-domain", "login": None, "user_id": None}


def parse_patch(text: str) -> dict | None:
    """The identity block of a `.patch` (git format-patch mbox): From name/email, Date, Subject."""
    if not text:
        return None
    m = _PATCH_FROM.search(text)
    if not m:
        return None
    d = _PATCH_DATE.search(text)
    s = _PATCH_SUBJ.search(text)
    return {"name": m.group(1).strip().strip('"'), "email": m.group(2).strip(),
            "date": d.group(1) if d else None,
            "subject": re.sub(r"^\[PATCH[^\]]*\]\s*", "", s.group(1)) if s else None}


class _Identities:
    def __init__(self):
        self.rows = {}

    def add(self, name, email, *, login=None, repo=None, date=None, source=None, role=None, count=True,
            fork=False):
        email = (email or "").strip()
        if not email or "@" not in email:
            return
        key = email.lower()
        cls = classify_email(email, name)
        row = self.rows.setdefault(key, {
            "email": email, "names": [], "logins": [], "kind": cls["kind"],
            "user_id": cls["user_id"], "repos": [], "roles": [], "sources": [],
            "first_seen": None, "last_seen": None, "commits": 0, "own_repo": False})
        if not fork:
            row["own_repo"] = True         # seen in a repository the target owns outright
        if name and name not in row["names"]:
            row["names"].append(name)
        for lg in (login, cls["login"]):
            if lg and lg not in row["logins"]:
                row["logins"].append(lg)
        if repo and repo not in row["repos"]:
            row["repos"].append(repo)
        if role and role not in row["roles"]:
            row["roles"].append(role)
        if source and source not in row["sources"]:
            row["sources"].append(source)
        if date:
            row["first_seen"] = min(row["first_seen"] or date, date)
            row["last_seen"] = max(row["last_seen"] or date, date)
        if count and source in ("patch", "api-commit"):
            row["commits"] += 1        # one commit is one commit, however many sources saw it

    def as_list(self):
        return sorted(self.rows.values(), key=lambda r: (-r["commits"], r["email"]))


# ------------------------------------------------------------------ collectors
def _profile_selectors(p: dict) -> dict:
    """Profile-level selectors for a user/org: emails, socials, links — the 'about' block."""
    if not p:
        return {}
    out = {"login": p.get("login"), "id": p.get("id"), "type": p.get("type"), "name": p.get("name"),
           "company": p.get("company"), "location": p.get("location"), "bio": p.get("bio") or p.get("description"),
           "email": p.get("email"), "blog": p.get("blog"), "twitter": p.get("twitter_username"),
           "created_at": p.get("created_at"), "updated_at": p.get("updated_at"),
           "public_repos": p.get("public_repos"), "followers": p.get("followers"),
           "html_url": p.get("html_url"), "socials": [], "emails": []}
    if p.get("email"):
        out["emails"].append(p["email"])
    if p.get("twitter_username"):
        out["socials"].append(f"https://twitter.com/{p['twitter_username']}")
    blog = (p.get("blog") or "").strip()
    if blog:
        if any(h in blog.lower() for h in _SOCIAL_HOSTS):
            out["socials"].append(blog if "://" in blog else "https://" + blog)
    text = " ".join(str(p.get(k) or "") for k in ("bio", "description", "company", "blog"))
    for e in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text):
        if e not in out["emails"]:
            out["emails"].append(e)
    for u in re.findall(r"https?://[^\s)\]]+", text):
        if any(h in u.lower() for h in _SOCIAL_HOSTS) and u not in out["socials"]:
            out["socials"].append(u)
    return out


def _user_social_accounts(http: _Http, login: str) -> list:
    """GET /users/<login>/social_accounts — the profile's declared social links (2023+ field)."""
    rows = http.json(f"/users/{login}/social_accounts") or []
    return [r.get("url") for r in rows if isinstance(r, dict) and r.get("url")]


def _sample_indices(total: int):
    if total <= SAMPLE_THRESHOLD:
        return list(range(total)), "all"
    return list(range(SAMPLE_EDGE)) + list(range(total - SAMPLE_EDGE, total)), "first2+last2"


def _repo_commits(http: _Http, owner: str, repo: str, ids: _Identities, fetch_patches: bool,
                  fork: bool = False) -> dict:
    """Sample a repository's default-branch history: first 2 + last 2 when > 10 commits.

    NOTE: `total` is estimated from /contributors contributions (capped at 500 authors, undercounts
    with anon, may 202 on first hit for large repos). The exact count is `?per_page=1` + the
    `Link: rel="last"` page number — a more reliable follow-up if the estimate ever mis-selects the
    oldest two."""
    full = f"{owner}/{repo}"
    # newest page first; Link header gives the last page -> total pages; we only need the newest 2
    # and the oldest 2, so at most two API calls plus the patches.
    newest = http.json(f"/repos/{full}/commits", {"per_page": PER_PAGE})
    if newest is None:
        return {"repo": full, "error": "commits unavailable (empty repo, private, or rate-limited)",
                "commits_total": None, "commits_sampled": []}
    total_pages = 1
    # count precisely when the first page is full: walk the Link header once
    if len(newest) == PER_PAGE:
        # GitHub's Link header is on the response; we don't keep it in json(), so probe cheaply
        # via the contributors endpoint which returns total contributions per login
        contrib = http.json(f"/repos/{full}/contributors", {"per_page": PER_PAGE, "anon": "1"}) or []
        total = sum(int(c.get("contributions") or 0) for c in contrib if isinstance(c, dict)) or len(newest)
    else:
        total = len(newest)
    if total > SAMPLE_THRESHOLD:
        head = newest[:SAMPLE_EDGE]
        if total <= PER_PAGE:
            tail = newest[-SAMPLE_EDGE:]
        else:
            # the oldest two live on the last page
            last_page = (total + PER_PAGE - 1) // PER_PAGE
            oldest = http.json(f"/repos/{full}/commits", {"per_page": PER_PAGE, "page": last_page}) or []
            tail = oldest[-SAMPLE_EDGE:] if len(oldest) >= SAMPLE_EDGE else oldest
            if len(tail) < SAMPLE_EDGE and last_page > 1:
                prev = http.json(f"/repos/{full}/commits", {"per_page": PER_PAGE, "page": last_page - 1}) or []
                tail = (prev[-(SAMPLE_EDGE - len(tail)):] + tail) if prev else tail
        picked, rule = head + tail, "first2+last2"
    else:
        picked, rule = newest, "all"
    sampled = []
    seen = set()
    for c in picked:
        sha = c.get("sha")
        if not sha or sha in seen:
            continue
        seen.add(sha)
        row = _commit_row(http, full, c, ids, fetch_patches, fork=fork)
        sampled.append(row)
    return {"repo": full, "commits_total": total, "sample_rule": rule, "commits_sampled": sampled}


def _commit_row(http: _Http, full: str, c: dict, ids: _Identities, fetch_patches: bool,
                fork: bool = False) -> dict:
    sha = c.get("sha")
    cm = c.get("commit") or {}
    author = cm.get("author") or {}
    committer = cm.get("committer") or {}
    a_login = (c.get("author") or {}).get("login")
    c_login = (c.get("committer") or {}).get("login")
    row = {"sha": sha, "url": f"{WEB}/{full}/commit/{sha}", "date": author.get("date"),
           "author": {"name": author.get("name"), "email": author.get("email"), "login": a_login},
           "committer": {"name": committer.get("name"), "email": committer.get("email"), "login": c_login},
           "message": (cm.get("message") or "").split("\n", 1)[0][:160], "patch": None}
    ids.add(author.get("name"), author.get("email"), login=a_login, repo=full, date=author.get("date"),
            source="api-commit", role="author", fork=fork)
    if committer.get("email") and committer.get("email") != author.get("email") \
            and "noreply@github.com" != (committer.get("email") or "").lower():
        ids.add(committer.get("name"), committer.get("email"), login=c_login, repo=full,
                date=committer.get("date"), source="api-commit", role="committer", fork=fork)
    if fetch_patches:
        # the .patch From: line is git's own record — it survives when the API author is null
        # (unlinked e-mail) and is what an analyst quotes as evidence
        txt = http.text(f"{WEB}/{full}/commit/{sha}.patch")
        p = parse_patch(txt)
        if p:
            row["patch"] = {"url": f"{WEB}/{full}/commit/{sha}.patch", **p}
            ids.add(p["name"], p["email"], login=a_login, repo=full, date=author.get("date"),
                    source="patch", role="author", fork=fork,
                    count=(p["email"].lower() != (author.get("email") or "").lower()))
    return row


def _repos_for(http: _Http, owner: str, is_org: bool, max_repos: int) -> list:
    path = f"/orgs/{owner}/repos" if is_org else f"/users/{owner}/repos"
    out, page = [], 1
    while len(out) < max_repos:
        rows = http.json(path, {"per_page": min(PER_PAGE, max_repos), "page": page,
                                "sort": "pushed", "type": "all" if is_org else "owner"})
        if not rows:
            break
        out.extend(rows)
        if len(rows) < PER_PAGE:
            break
        page += 1
    # own work first: forks carry the upstream's committers, so they go last and are flagged
    out.sort(key=lambda r: (bool(r.get("fork")), -(r.get("stargazers_count") or 0)))
    return out[:max_repos]


def _contributors(http: _Http, owner: str, repos: list, max_contrib: int) -> list:
    """Top contributors across the owner's repositories, with their profile selectors."""
    tally = {}
    for r in repos:
        rows = http.json(f"/repos/{r['full_name']}/contributors", {"per_page": 30}) or []
        for c in rows:
            if not isinstance(c, dict) or not c.get("login"):
                continue
            t = tally.setdefault(c["login"], {"login": c["login"], "id": c.get("id"),
                                              "contributions": 0, "repos": [], "html_url": c.get("html_url")})
            t["contributions"] += int(c.get("contributions") or 0)
            t["repos"].append(r["full_name"])
    top = sorted(tally.values(), key=lambda t: -t["contributions"])[:max_contrib]
    for t in top:
        t["profile"] = _profile_selectors(http.json(f"/users/{t['login']}") or {})
        t["profile"]["socials"] = list(dict.fromkeys(
            (t["profile"].get("socials") or []) + _user_social_accounts(http, t["login"])))
        t["is_bot"] = bool(_BOT.search(t["login"]))
    return top


# ------------------------------------------------------------------ pivot shaping
def _pivots(result: dict) -> list:
    piv = []
    for ident in result.get("identities") or []:
        if ident["kind"] == "bot":
            continue
        if not ident.get("own_repo"):
            # seen only inside forked repositories: the UPSTREAM author's identity, never a pivot
            # for this target (a fork of a captcha library does not make its author the operator)
            continue
        note = ("GitHub no-reply address — binds numeric user id to login; NOT a mailbox, but a stable "
                "identity join key across repositories" if ident["kind"] == "noreply" else
                "commit author e-mail as recorded by git — pivot to /breach-deep, /intelx, reverse-WHOIS; "
                "it identifies the COMMITTER, not necessarily the repository owner")
        piv.append({"kind": "github_commit_email" if ident["kind"] != "noreply" else "github_noreply",
                    "value": ident["email"], "confidence": "high" if ident["logins"] else "medium",
                    "note": note, "names": ident["names"], "logins": ident["logins"],
                    "repos": ident["repos"], "commits": ident["commits"],
                    "first_seen": ident["first_seen"], "last_seen": ident["last_seen"]})
        if ident["kind"] != "noreply":
            piv.append({"kind": "email", "value": ident["email"], "confidence": "high" if ident["logins"] else "medium",
                        "note": f"GitHub commit e-mail ({', '.join(ident['names'][:2]) or 'no name'}; "
                                f"login {', '.join(ident['logins']) or '—'})"})
    prof = result.get("profile") or {}
    # a no-reply address embeds the login AT COMMIT TIME: when it differs from the account's current
    # login the account was renamed — the old handle is a username pivot across other platforms
    cur = (prof.get("login") or "").lower()
    for ident in result.get("identities") or []:
        if ident["kind"] == "noreply" and ident.get("own_repo"):
            m = _NOREPLY.match(ident["email"])
            old = m.group(2) if m else None
            if old and cur and old.lower() != cur and (ident.get("user_id") in (None, prof.get("id"))):
                piv.append({"kind": "username", "value": old, "confidence": "high",
                            "note": f"former GitHub login of user id {ident.get('user_id') or prof.get('id')} "
                                    f"(now '{prof.get('login')}') — recorded in the commit no-reply address; "
                                    f"enumerate the handle on other platforms"})
    for e in prof.get("emails") or []:
        piv.append({"kind": "email", "value": e, "confidence": "high", "note": "GitHub profile e-mail"})
    for s in prof.get("socials") or []:
        piv.append({"kind": "social", "value": s, "confidence": "medium", "note": "GitHub profile link"})
    if prof.get("blog") and not any(h in prof["blog"].lower() for h in _SOCIAL_HOSTS):
        piv.append({"kind": "domain", "value": urlparse(prof["blog"] if "://" in prof["blog"] else "https://" + prof["blog"]).hostname,
                    "confidence": "medium", "note": "GitHub profile website"})
    for t in result.get("contributors") or []:
        if t.get("is_bot"):
            continue
        for e in (t.get("profile") or {}).get("emails") or []:
            piv.append({"kind": "email", "value": e, "confidence": "medium",
                        "note": f"profile e-mail of top contributor {t['login']} — a collaborator, not the owner"})
        for s in (t.get("profile") or {}).get("socials") or []:
            piv.append({"kind": "social", "value": s, "confidence": "low",
                        "note": f"profile link of top contributor {t['login']}"})
    return piv


# ------------------------------------------------------------------ entry
def harvest(target: str, *, max_repos: int = MAX_REPOS_DEFAULT, max_contributors: int = MAX_CONTRIBUTORS_DEFAULT,
            patches: bool = True, token: str = None, timeout: int = 25) -> dict:
    t = parse_target(target)
    http = _Http(token=token if token is not None else _token(), timeout=timeout)
    ids = _Identities()
    out = {"meta": {"kind": "github", "host": f"github.com/{t['owner']}", "source": target,
                    "collector": "wp_github", "collected_at": _now()},
           "target": target, "kind": t["kind"], "owner": t["owner"], "collected_at": _now(),
           "sample_rule": f">{SAMPLE_THRESHOLD} commits -> first {SAMPLE_EDGE} + last {SAMPLE_EDGE}",
           "profile": {}, "repos": [], "contributors": [], "identities": [], "pivots": [],
           "capability": {"authenticated": bool(http.token),
                          "note": "keyless: 60 api.github.com requests/hour per IP; set GITHUB_TOKEN for 5000/h"}}

    if t["kind"] == "commit":
        full = f"{t['owner']}/{t['repo']}"
        c = http.json(f"/repos/{full}/commits/{t['sha']}")
        if c:
            row = _commit_row(http, full, c, ids, patches)
        else:
            txt = http.text(f"{WEB}/{full}/commit/{t['sha']}.patch")
            p = parse_patch(txt)
            row = {"sha": t["sha"], "url": f"{WEB}/{full}/commit/{t['sha']}", "patch": p and {"url": f"{WEB}/{full}/commit/{t['sha']}.patch", **p}}
            if p:
                ids.add(p["name"], p["email"], repo=full, source="patch", role="author")
        out["repos"].append({"repo": full, "commits_total": None, "sample_rule": "single", "commits_sampled": [row]})
        out["profile"] = _profile_selectors(http.json(f"/users/{t['owner']}") or {})
    elif t["kind"] == "repo":
        full = f"{t['owner']}/{t['repo']}"
        meta = http.json(f"/repos/{full}") or {}
        r = _repo_commits(http, t["owner"], t["repo"], ids, patches, fork=bool(meta.get("fork")))
        r.update({"fork": meta.get("fork"), "parent": (meta.get("parent") or {}).get("full_name"),
                  "created_at": meta.get("created_at"), "pushed_at": meta.get("pushed_at"),
                  "description": meta.get("description"), "homepage": meta.get("homepage")})
        out["repos"].append(r)
        out["profile"] = _profile_selectors(http.json(f"/users/{t['owner']}") or {})
        out["contributors"] = _contributors(http, t["owner"], [{"full_name": full}], max_contributors)
    else:
        prof = http.json(f"/users/{t['owner']}") or {}
        is_org = (prof.get("type") == "Organization")
        if is_org:
            prof = http.json(f"/orgs/{t['owner']}") or prof
        out["profile"] = _profile_selectors(prof)
        out["profile"]["socials"] = list(dict.fromkeys(
            (out["profile"].get("socials") or []) + _user_social_accounts(http, t["owner"])))
        out["is_org"] = is_org
        repos = _repos_for(http, t["owner"], is_org, max_repos)
        for r in repos:
            row = _repo_commits(http, t["owner"], r["name"], ids, patches, fork=bool(r.get("fork")))
            row.update({"fork": r.get("fork"), "created_at": r.get("created_at"), "pushed_at": r.get("pushed_at"),
                        "description": r.get("description"), "homepage": r.get("homepage"),
                        "stars": r.get("stargazers_count"), "language": r.get("language")})
            out["repos"].append(row)
        if is_org:
            members = http.json(f"/orgs/{t['owner']}/public_members", {"per_page": 100}) or []
            out["public_members"] = [m.get("login") for m in members if isinstance(m, dict)]
        # a fork's contributors are the UPSTREAM project's people — only the target's own repos count
        out["contributors"] = _contributors(http, t["owner"], [r for r in repos if not r.get("fork")], max_contributors)

    out["identities"] = ids.as_list()
    out["pivots"] = _pivots(out)
    out["api"] = {"calls": http.calls, "rate_limit_remaining": http.remaining, "errors": http.errors[:10]}
    if api_usage is not None:
        try:
            api_usage.record("github", http.calls, note=target, credits=0)
        except Exception:
            pass
    return out


def _now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def summarize(res: dict) -> str:
    ids = [i for i in res.get("identities") or [] if i["kind"] != "bot"]
    lines = [f"GitHub harvest — {res['target']} ({res['kind']}{', organisation' if res.get('is_org') else ''}): "
             f"{len(res.get('repos') or [])} repo(s), {sum(len(r.get('commits_sampled') or []) for r in res.get('repos') or [])} "
             f"commit(s) sampled [{res.get('sample_rule')}], {len(ids)} identity(ies)"]
    for i in ids[:25]:
        lines.append(f"  {i['email']:<48} {i['kind']:<10} {', '.join(i['names'][:2]) or '—':<28} "
                     f"login={', '.join(i['logins']) or '—'}  commits={i['commits']}  "
                     f"{(i['first_seen'] or '')[:10]}..{(i['last_seen'] or '')[:10]}  repos={len(i['repos'])}")
    p = res.get("profile") or {}
    if p.get("emails") or p.get("socials") or p.get("blog"):
        lines.append(f"  profile: emails={p.get('emails')} socials={p.get('socials')} blog={p.get('blog')} "
                     f"company={p.get('company')} location={p.get('location')}")
    for t in (res.get("contributors") or [])[:10]:
        pr = t.get("profile") or {}
        lines.append(f"  contributor {t['login']:<22} contributions={t['contributions']:<5} "
                     f"emails={pr.get('emails')} socials={pr.get('socials')}")
    a = res.get("api") or {}
    lines.append(f"  api calls={a.get('calls')} remaining={a.get('rate_limit_remaining')}"
                 + (f" errors={a['errors']}" if a.get("errors") else ""))
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="GitHub committer-identity harvest (user / org / repo / commit URL)")
    ap.add_argument("target", help="login, owner/repo, or any github.com URL (incl. a commit URL)")
    ap.add_argument("-o", "--out", help="write JSON here")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("--max-repos", type=int, default=MAX_REPOS_DEFAULT)
    ap.add_argument("--max-contributors", type=int, default=MAX_CONTRIBUTORS_DEFAULT)
    ap.add_argument("--no-patches", action="store_true", help="API commit metadata only; skip the .patch From: lines")
    ap.add_argument("--timeout", type=int, default=25)
    a = ap.parse_args(argv)
    res = harvest(a.target, max_repos=a.max_repos, max_contributors=a.max_contributors,
                  patches=not a.no_patches, timeout=a.timeout)
    js = json.dumps(res, ensure_ascii=False, indent=2 if a.pretty else None)
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        open(a.out, "w", encoding="utf-8").write(js + "\n")
        print(f"wrote {a.out}", file=sys.stderr)
    else:
        print(js)
    print(summarize(res), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
