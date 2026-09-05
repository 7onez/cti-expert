"""Regression: wp_github committer-identity harvest + its KB ingest.

  1. commit-URL: the `.patch` From: line is parsed to name+email; a no-reply address becomes a
     `github_noreply` pivot (not an email IOC) and, when the login in it differs from the account's
     current login, a `username` pivot tagged former-login.
  2. user walk: >10-commit repos contribute first-2 + last-2, ≤10 contribute all; identities seen
     ONLY in forked repos (upstream authors) never become pivots (RULE 5).
  3. one commit is counted once across the API row and the .patch row.
  4. ingest (meta.kind=='github'): identities are recorded as FACTS on the account node / joined on
     the `email` node — never a registrant/owner edge; a github_noreply value is an indicator, not
     an email entity.
Synthetic data only: an `example` org, RFC-style fake uid, example.com addresses. Network stubbed."""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "intel_engine", "WebPivot", "tools"))
sys.path.insert(0, os.path.join(ROOT, "intel_engine", "tools", "kb"))

import wp_github as g  # noqa: E402
import ingest_webpivot as iw  # noqa: E402
import knowledge_base as kbm  # noqa: E402


def _commit(sha, name, email, date, login="devowner", msg="x"):
    return {"sha": sha, "commit": {"author": {"name": name, "email": email, "date": date},
                                   "committer": {"name": name, "email": email, "date": date}, "message": msg},
            "author": {"login": login}, "committer": {"login": login}}


def _patch(sha, name, email, date="Thu, 27 Jun 2019 12:35:17 +0700", subject="Delete x"):
    return (f"From {sha} Mon Sep 17 00:00:00 2001\nFrom: {name} <{email}>\nDate: {date}\n"
            f"Subject: [PATCH] {subject}\n\n--- a/x\n+++ b/x\n")


class _FakeHttp:
    """Serves wp_github's _Http.json/.text from a fixture routing table; no network."""
    def __init__(self, routes, texts):
        self.routes, self.texts = routes, texts
        self.token, self.calls, self.remaining, self.errors = "t", 0, 4999, []

    def json(self, path, params=None):
        self.calls += 1
        return self.routes.get(path.split("?")[0])

    def text(self, url):
        self.calls += 1
        return self.texts.get(url)


def _install(routes, texts):
    orig = g._Http
    g._Http = lambda *a, **k: _FakeHttp(routes, texts)
    return orig


def test_commit_url_patch_and_former_login():
    sha = "ab" * 20                       # synthetic 40-hex sha
    routes = {"/repos/example/blog/commits/" + sha:
              _commit(sha, "Test Committer", "900001+oldlogin@users.noreply.github.com",
                      "2019-06-27T05:35:17Z", login="newlogin"),
              "/users/example": {"login": "newlogin", "id": 900001, "type": "User",
                                 "blog": "https://example.com", "html_url": "https://github.com/newlogin"}}
    texts = {f"https://github.com/example/blog/commit/{sha}.patch":
             _patch(sha, "Test Committer", "900001+oldlogin@users.noreply.github.com")}
    orig = _install(routes, texts)
    try:
        r = g.harvest(f"https://github.com/example/blog/commit/{sha}")
    finally:
        g._Http = orig
    ident = r["identities"][0]
    assert ident["email"] == "900001+oldlogin@users.noreply.github.com"
    assert ident["kind"] == "noreply" and ident["user_id"] == 900001 and ident["commits"] == 1
    kinds = {(p["kind"], p["value"]) for p in r["pivots"]}
    assert ("github_noreply", ident["email"]) in kinds
    assert ("username", "oldlogin") in kinds, "former login not surfaced as a username pivot"
    assert not any(p["kind"] == "email" for p in r["pivots"]), "a no-reply address must not be an email IOC"


def test_user_walk_sampling_and_fork_exclusion():
    # own repo with >10 commits -> first 2 + last 2; forked repo -> upstream authors excluded.
    full_first = [_commit(f"h{i:02d}", "Owner", "owner@example.com", "2024-02-01T00:00:00Z")
                  for i in range(g.PER_PAGE)]          # a full page + total>PER_PAGE forces the last-page fetch
    oldest = [_commit("old0", "Owner", "owner@example.com", "2020-01-01T00:00:00Z"),
              _commit("old1", "Owner", "owner@example.com", "2020-01-02T00:00:00Z")]
    routes = {
        "/users/example": {"login": "example", "id": 900001, "type": "User"},
        "/users/example/repos": [
            {"name": "own", "full_name": "example/own", "fork": False, "stargazers_count": 9},
            {"name": "forked", "full_name": "example/forked", "fork": True, "stargazers_count": 1}],
        "/repos/example/own/commits": full_first,
        "/repos/example/own/contributors": [{"login": "example", "contributions": 140}],
        "/repos/example/forked/commits": [_commit("f0", "Upstream Dev", "upstream@other.example",
                                                  "2022-01-01T00:00:00Z", login="upstream")],
        "/repos/example/forked/contributors": [{"login": "upstream", "contributions": 40}],
    }

    # the oldest-two live on the last page; any explicit ?page= request returns the tail
    class _PagedHttp(_FakeHttp):
        def json(self, path, params=None):
            self.calls += 1
            if path == "/repos/example/own/commits" and (params or {}).get("page"):
                return oldest
            return self.routes.get(path.split("?")[0])

    orig = g._Http
    g._Http = lambda *a, **k: _PagedHttp(routes, {})
    try:
        r = g.harvest("example")
    finally:
        g._Http = orig
    own = next(rp for rp in r["repos"] if rp["repo"] == "example/own")
    assert own["commits_total"] > 10 and own["sample_rule"] == "first2+last2", own
    assert {c["sha"] for c in own["commits_sampled"]} == {"h00", "h01", "old0", "old1"}, own["commits_sampled"]
    own_emails = {i["email"] for i in r["identities"] if i.get("own_repo")}
    assert "owner@example.com" in own_emails
    assert "upstream@other.example" not in own_emails, "a fork's upstream author leaked as own-repo"
    assert not any(p.get("value") == "upstream@other.example" for p in r["pivots"]), "upstream author became a pivot (RULE 5)"


def test_ingest_records_facts_not_owner_edges():
    harvest = {"meta": {"kind": "github", "host": "github.com/example"},
               "owner": "example", "is_org": False,
               "profile": {"login": "example", "id": 5, "emails": ["dev@example.com"], "socials": [],
                           "blog": "https://example.com"},
               "public_members": [],
               "identities": [{"email": "owner@example.com", "names": ["Owner"], "logins": ["example"],
                               "kind": "personal", "user_id": None, "own_repo": True, "repos": ["example/own"],
                               "commits": 3},
                              {"email": "900001+oldlogin@users.noreply.github.com", "names": ["O"],
                               "logins": ["example"], "kind": "noreply", "user_id": 900001,
                               "own_repo": True, "repos": ["example/own"], "commits": 1}],
               "pivots": [{"kind": "username", "value": "oldlogin", "confidence": "high"}]}
    with tempfile.TemporaryDirectory() as tmp:
        kb = kbm.KB(os.path.join(tmp, "knowledge"))
        p = os.path.join(tmp, "github.com_example.json")
        json.dump(harvest, open(p, "w"))
        n = iw.ingest_file(kb, p)
    assert n > 0
    edges = [(e["src"], e["rel"], e["dst_type"], e["dst"]) for e in kb.edges()]
    # the account commits_as the real email (join node) and the noreply INDICATOR (not an email node)
    assert ("social:github:example", "commits_as", "email", "owner@example.com") in edges
    assert any(r == "commits_as" and dt == "indicator" and d.startswith("github_noreply:")
               for _, r, dt, d in edges), "noreply must be an indicator, not an email entity"
    # never a registrant / owner edge from a commit identity
    assert not any(r in ("registered_by", "owns", "uses_contact") for _, r, _, _ in edges), \
        "a commit identity must not become an owner/registrant edge"
    assert ("social:github:example", "alias_of", "indicator", "social:github:oldlogin") in edges


_TESTS = [
    test_commit_url_patch_and_former_login,
    test_user_walk_sampling_and_fork_exclusion,
    test_ingest_records_facts_not_owner_edges,
]


def check():
    passed = failed = 0
    lines = []
    for test in _TESTS:
        label = test.__name__.removeprefix("test_").replace("_", " ")
        try:
            test()
        except Exception as exc:  # noqa: BLE001
            failed += 1
            lines.append(("FAIL", f"{label}: {exc}"))
        else:
            passed += 1
            lines.append(("ok", label))
    return passed, failed, lines


if __name__ == "__main__":
    _passed, _failed, _lines = check()
    for _status, _label in _lines:
        print(("ok" if _status == "ok" else "FAIL") + "  " + _label)
    raise SystemExit(bool(_failed))
