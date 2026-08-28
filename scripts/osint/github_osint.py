#!/usr/bin/env python3
"""github_osint.py — GitHub user / org / repo reconnaissance, and the leaked-secret question.

Backs /github-osint and /secrets. Both ask the same thing of the same API, so they share one tool
rather than becoming two that drift.

KEYLESS at 60 requests/hour, which is enough for a profile pass and nothing more. Set GITHUB_TOKEN
for 5000/hr. The rate-limit state is ALWAYS reported: a 403 that silently returns nothing looks
exactly like an account that does not exist, and mistaking one for the other is how a real actor
gets written off as absent.

CODE SEARCH REQUIRES AUTH. Without a token, /secrets cannot search — so the tool emits the exact
queries to run instead of pretending it looked. It never claims to have searched what it did not.

Committer emails are the high-value artifact here: a public commit exposes the author's email,
which reverse-pivots to other accounts and to leak corpora.

Usage:
  github_osint.py octocat
  github_osint.py github.com/org/repo --repo
  github_osint.py acme --secrets --pretty
"""
# /// script
# requires-python = ">=3.9"
# ///
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"
UA = "cti-expert/github_osint (OSINT research)"


def _h():
    h = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def _get(path, timeout=20):
    url = path if path.startswith("http") else API + path
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=_h()), timeout=timeout) as r:
            return json.load(r), None, dict(r.headers)
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}", dict(e.headers or {})
    except Exception as e:  # noqa: BLE001
        return None, type(e).__name__, {}


def rate_state():
    d, err, _ = _get("/rate_limit")
    if err or not d:
        return {"status": f"unknown ({err})"}
    c = (d.get("resources") or {}).get("core") or {}
    return {"remaining": c.get("remaining"), "limit": c.get("limit"),
            "authenticated": bool(os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"))}


def profile(name):
    d, err, _ = _get(f"/users/{urllib.parse.quote(name)}")
    if err:
        return {"status": f"unavailable ({err})"}
    return {"status": "ok", "login": d.get("login"), "type": d.get("type"),
            "name": d.get("name"), "company": d.get("company"), "blog": d.get("blog"),
            "location": d.get("location"), "email": d.get("email"),
            "twitter": d.get("twitter_username"), "created": d.get("created_at"),
            "public_repos": d.get("public_repos"), "followers": d.get("followers")}


def repos(name, cap=30):
    d, err, _ = _get(f"/users/{urllib.parse.quote(name)}/repos?per_page={cap}&sort=pushed")
    if err or not isinstance(d, list):
        return {"status": f"unavailable ({err})", "items": []}
    return {"status": "ok", "items": [
        {"name": r.get("full_name"), "pushed": r.get("pushed_at"), "fork": r.get("fork"),
         "lang": r.get("language"), "stars": r.get("stargazers_count"),
         "homepage": r.get("homepage")} for r in d]}


def commit_emails(full_name, cap=30):
    """Public commits leak the author's email — usually the strongest pivot on the account."""
    d, err, _ = _get(f"/repos/{full_name}/commits?per_page={cap}")
    if err or not isinstance(d, list):
        return {"status": f"unavailable ({err})", "identities": []}
    seen = {}
    for c in d:
        for who in ("author", "committer"):
            g = ((c.get("commit") or {}).get(who) or {})
            em, nm = g.get("email"), g.get("name")
            if em and not em.endswith("@users.noreply.github.com"):
                seen.setdefault(em, {"email": em, "names": set()})["names"].add(nm)
    return {"status": "ok",
            "identities": [{"email": k, "names": sorted(x for x in v["names"] if x)}
                           for k, v in seen.items()]}


def secret_queries(target):
    """Queries for the analyst to run. Emitted, never executed — code search needs auth."""
    t = target
    return {
        "github_code_search": [f'"{t}" AND (password OR passwd OR secret)',
                               f'"{t}" filename:.env', f'"{t}" filename:config.json',
                               f'"{t}" AWS_SECRET_ACCESS_KEY', f'org:{t} filename:.npmrc _auth'],
        "external": [f'https://grep.app/search?q={urllib.parse.quote(t)}',
                     f'https://search.marcia.dev/?q={urllib.parse.quote(t)}'],
        "local_tools": [f"trufflehog github --org={t}", f"gitleaks detect --source ."],
        "note": ("GitHub code search requires authentication, so these are NOT run here. Running "
                 "them signs in as you — that is an attributable action, which is why the tool "
                 "hands you the query instead of quietly performing it."),
    }


def main():
    ap = argparse.ArgumentParser(description="GitHub user/org/repo recon and secret-hunt queries.")
    ap.add_argument("target", help="username, org, owner/repo, or a github.com URL")
    ap.add_argument("--repo", action="store_true", help="treat target as owner/repo")
    ap.add_argument("--secrets", action="store_true", help="emit leaked-secret hunt queries")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    t = re.sub(r"^https?://(www\.)?github\.com/", "", a.target.strip()).strip("/")
    out = {"target": t, "rate_limit": rate_state()}
    rl = out["rate_limit"]
    if rl.get("remaining") == 0:
        out["warning"] = ("GitHub rate limit EXHAUSTED — an empty result below means 'not "
                          "queried', not 'does not exist'. Set GITHUB_TOKEN for 5000/hr.")

    if a.repo or ("/" in t and len(t.split("/")) == 2):
        out["kind"] = "repo"
        d, err, _ = _get(f"/repos/{t}")
        out["repo"] = {"status": f"unavailable ({err})"} if err else {
            "status": "ok", "full_name": d.get("full_name"), "owner": (d.get("owner") or {}).get("login"),
            "created": d.get("created_at"), "pushed": d.get("pushed_at"),
            "homepage": d.get("homepage"), "lang": d.get("language"), "forks": d.get("forks_count")}
        out["commit_identities"] = commit_emails(t)
    else:
        out["kind"] = "account"
        out["profile"] = profile(t)
        out["repos"] = repos(t)

    if a.secrets:
        out["secret_hunt"] = secret_queries(t)

    p = out.get("profile") or {}
    print(f"{t}: {out['kind']}"
          + (f" — {p.get('type')}, {p.get('public_repos')} repos" if p.get("status") == "ok" else "")
          + f"  [rate {rl.get('remaining')}/{rl.get('limit')}"
          + (", authed" if rl.get("authenticated") else ", KEYLESS") + "]", file=sys.stderr)
    if out.get("warning"):
        print(f"  ⚠ {out['warning']}", file=sys.stderr)
    ids = (out.get("commit_identities") or {}).get("identities") or []
    for i in ids[:5]:
        print(f"  identity: {i['email']}  {', '.join(i['names'][:2])}", file=sys.stderr)
    txt = json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)
    print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
