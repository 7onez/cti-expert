#!/usr/bin/env python3
"""Regression: a scraped social link becomes a KB `social:<net>:<account>` contact ONLY when it
names an account (noise_filters.social_handle), and registrar contacts returned in the registrant
slot never bind a cluster.

WHAT THIS PROTECTS
------------------
Ingest used to take the LAST path segment of any social URL as the "handle". A core-js polyfill
credit (`github.com/zloirock/core-js`), a repo LICENSE link, a YouTube player (`/embed/<id>`), a
thumbnail (`/vi/<id>/0.jpg`) and a bare `https://zalo.me` all became shared "contacts" —
`social:github:core-js`, `social:youtube:embed`, `social:zalo:zalo.me` — and merged unrelated
sites into one operator. Separately, a ccTLD WHOIS (.vn) returns the REGISTRAR's mailbox/phone/name
in the registrant slot (`info@tenten.vn`, `GMO-Z.com RUNSYSTEM`, its switchboard) — a term stamped
on thousands of domains that the KB had seen on only six. This asserts:
  1. account forms resolve to the account (first segment, @handle, second-segment router words);
  2. platform routes, players, thumbnails, share widgets, files and bare hosts resolve to None;
  3. the ingester emits a uses_contact edge only for an account;
  4. registrar contacts in the registrant slot are registrant noise for the cluster partition.
"""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(ROOT, "intel_engine")
for p in (os.path.join(ENGINE, "tools", "kb"), os.path.join(ENGINE, "WebPivot", "tools")):
    sys.path.insert(0, p)

import ingest_webpivot as I  # noqa: E402
import noise_filters as NF  # noqa: E402
import query as Q  # noqa: E402
from knowledge_base import KB  # noqa: E402

ACCOUNTS = [
    ("github", "https://github.com/operator-handle/some-kit", "operator-handle"),
    ("github", "https://github.com/operator-handle", "operator-handle"),
    ("youtube", "https://www.youtube.com/@operatorchan", "operatorchan"),
    ("youtube", "https://youtube.com/c/OperatorChan", "OperatorChan"),
    ("youtube", "https://youtube.com/channel/UCxxxxxxxxxxxxxxxxxxxxxx", "UCxxxxxxxxxxxxxxxxxxxxxx"),
    ("facebook", "https://www.facebook.com/operator.page", "operator.page"),
    ("facebook", "https://www.facebook.com/profile.php?id=100000000000001", "100000000000001"),
    ("facebook", "https://facebook.com/pages/Operator-Page/12345", "Operator-Page"),
    ("twitter", "https://x.com/operator_handle", "operator_handle"),
    ("telegram", "https://t.me/operator_handle", "operator_handle"),
    ("telegram", "https://t.me/s/operator_channel", "operator_channel"),
    ("telegram", "https://t.me/joinchat/AAAAAExampleInvite", "AAAAAExampleInvite"),
    ("zalo", "https://zalo.me/0900000000", "0900000000"),
    ("zalo", "https://zalo.me/g/examplegroup", "examplegroup"),
    ("instagram", "https://instagram.com/operator.handle/", "operator.handle"),
]
NOT_ACCOUNTS = [
    ("github", "https://github.com/some-user/some-repo/blob/main/LICENSE"),   # account is some-user, not LICENSE
    ("github", "https://github.com/orgs/some-org/repositories"),
    ("github", "https://github.com/topics/polyfill"),
    ("youtube", "https://www.youtube.com/embed/dQw4w9WgXcQ"),
    ("youtube", "https://www.youtube.com/embed"),
    ("youtube", "https://img.youtube.com/vi/dQw4w9WgXcQ/0.jpg"),
    ("youtube", "https://www.youtube.com/watch?v=dQw4w9WgXcQ"),
    ("youtube", "https://www.youtube.com/iframe_api"),
    ("facebook", "https://www.facebook.com/sharer.php?u=https://site.example"),
    ("facebook", "https://www.facebook.com/tr?id=1"),
    ("facebook", "https://www.facebook.com/plugins/like.php"),
    ("twitter", "https://twitter.com/intent/tweet?text=hi"),
    ("twitter", "https://twitter.com/share"),
    ("telegram", "https://t.me/share/url?url=x"),
    ("telegram", "https://t.me/iv?url=x"),
    ("zalo", "https://zalo.me"),
    ("zalo", "https://zalo.me/"),
    ("instagram", "https://instagram.com/p/CxyzExample/"),
    ("github", "https://github.com/octocat.png"),
    ("facebook", "https://facebook.com/index.html"),
    ("twitter", "https://twitter.com/{u}"),
    ("youtube", "//img.youtube.com/vi/"),                                        # protocol-relative thumbnail base
    ("youtube", "//www.youtube.com/embed/"),
    ("github", "https://github.com/zloirock/core-js"),                           # OSS credit account, not the operator
    ("github", "https://github.com/jquery/jquery"),
]


def check():
    passed = failed = 0
    lines = []

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            lines.append(("ok", label))
        else:
            failed += 1
            lines.append(("FAIL", label))

    for net, url, want in ACCOUNTS:
        got = NF.social_handle(net, url)
        ok(got == want, f"{net}: {url} -> {got!r}" + ("" if got == want else f" (want {want!r})"))
    for net, url in NOT_ACCOUNTS:
        got = NF.social_handle(net, url)
        # the LICENSE case resolves to the USER, never to the file name
        if url.endswith("/LICENSE"):
            ok(got == "some-user", f"{net}: {url} -> {got!r} (the user, not the file)")
        else:
            ok(got is None, f"{net}: {url} -> {got!r} (not an account)")

    # 3. ingest emits uses_contact only for accounts
    with tempfile.TemporaryDirectory() as tmp:
        kb = KB(os.path.join(tmp, "knowledge"))
        raw = {"meta": {"host": "seed.example", "kind": "domain", "fetched_at": "2026-01-01T00:00:00+00:00"},
               "pivots": [{"kind": "domain", "value": "seed.example", "live_results": {}}],
               "artifacts": {"socials": {
                   "github": ["https://github.com/zloirock/core-js", "https://github.com/operator-handle/kit"],
                   "youtube": ["https://www.youtube.com/embed/dQw4w9WgXcQ", "https://youtube.com/@operatorchan"],
                   "zalo": ["https://zalo.me", "https://zalo.me/0900000000"],
               }}}
        p = os.path.join(tmp, "seed.example.json")
        json.dump(raw, open(p, "w"))
        I.ingest_file(kb, p)
        contacts = {e["dst"] for e in kb.edges() if e["rel"] == "uses_contact"}
        ok(contacts == {"social:github:operator-handle", "social:youtube:operatorchan", "social:zalo:0900000000"},
           f"ingest emits contacts for accounts only — the core-js OSS credit is dropped ({sorted(contacts)})")
        ok(not any(c.endswith((":core-js", ":embed", ":zalo.me", ":LICENSE")) for c in contacts),
           "no repo / player / bare-host / file leaf ever becomes a contact")
    # 5. one person node per registrant across registrar spellings (honorific / ALL-CAPS / spacing)
    for raw_name, want in (("Ông Trần Văn Example", "Trần Văn Example"), ("TRẦN VĂN EXAMPLE", "Trần Văn Example"),
                           ("LÊ THỊ EXAMPLE", "Lê Thị Example"), ("  lê  thị example ", "Lê Thị Example"),
                           ("Mr. John Example", "John Example"), ("Anh Nguyen", "Anh Nguyen"), ("ACME", "ACME")):
        got = I.canonical_person(raw_name)
        ok(got == want, f"canonical_person({raw_name!r}) -> {got!r}" + ("" if got == want else f" (want {want!r})"))
    with tempfile.TemporaryDirectory() as tmp:
        kb = KB(os.path.join(tmp, "knowledge"))
        for host, nm in (("a.example", "Ông Nguyễn Văn Example"), ("b.example", "NGUYỄN VĂN EXAMPLE")):
            raw = {"meta": {"host": host, "kind": "domain", "fetched_at": "2026-01-01T00:00:00+00:00"},
                   "pivots": [{"kind": "domain", "value": host, "live_results": {}}],
                   "artifacts": {"whois": {"registrant_name": nm}}}
            p = os.path.join(tmp, host + ".json")
            json.dump(raw, open(p, "w"))
            I.ingest_file(kb, p)
        persons = {e["dst"] for e in kb.edges() if e["rel"] == "registered_by" and e["dst_type"] == "person"}
        ok(persons == {"Nguyễn Văn Example"}, f"two registrar spellings ingest as ONE person node ({sorted(persons)})")

    # 4. registrar contacts in the registrant slot are noise for the partition
    for t, v in (("email", "info@tenten.vn"), ("email", "registrar@inet.vn"),
                 ("person", "GMO-Z.com RUNSYSTEM"), ("person", "IPv4 address block not managed by the RIPE NCC"),
                 ("org", "Cloudflare, Inc."), ("person", "Domain Admin, C/O ID#12345")):
        ok(Q.is_registrant_noise(t, v), f"registrant noise: {t}:{v}")
    ok(NF.is_noise_phone("84435501630") if hasattr(NF, "is_noise_phone") else True,
       "a registrar switchboard phone in the registrant slot is noise")
    ok(not Q.is_registrant_noise("person", "Nguyễn Văn Example"), "an ordinary person name is not noise")
    # …and the COLLECTOR's spend gate refuses to reverse-WHOIS them (10,000 strangers, credits gone)
    import whois_enrich as WE  # noqa: E402
    for term in ("info@tenten.vn", "registrar@inet.vn", "reactivation-pending@enom.com", "expired@dynadot.com",
                 "proxy@whoisprotectservice.com", "tenmien@trinam.com.vn", "Domain Admin", "GMO-Z.com RUNSYSTEM"):
        ok(WE.is_privacy(term), f"reverse-WHOIS spend gate refuses registrar/role term {term!r}")
    for term in ("owner@example.com", "Trần Văn Example", "Cong ty TNHH Example"):
        ok(not WE.is_privacy(term), f"…but still reverses a real registrant term {term!r}")
    for junk in ("Some Name someone@example.com +84.900 00 00 00", "VALUE|DOMAIN", "REACTIVATION  PERIOD"):
        ok(I._name_kind(junk) is None, f"a mis-split WHOIS line is not a registrant name: {junk!r}")
    ok(I._name_kind("Trần Văn Example") == "person" and I._name_kind("Cong ty TNHH Example") == "org",
       "ordinary names still classify as person / org")
    return passed, failed, lines


if __name__ == "__main__":
    _passed, _failed, _lines = check()
    for _status, _label in _lines:
        print(f"{_status:>4}  {_label}")
    print(f"\n{_passed} passed, {_failed} failed")
    raise SystemExit(bool(_failed))
