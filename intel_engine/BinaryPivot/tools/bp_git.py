#!/usr/bin/env python3
"""
bp_git.py — leaked-source `.git` forensics and project-identifier sweep.

Leaked or sold source trees often ship with their version-control directory still inside — a
`.git/` beside the code, a nested submodule `.git/`, or a bare repository. That directory keeps
what the visible tree no longer shows:

  * config            remote URLs (the original hosting account / org), user.name / user.email
  * logs/HEAD, logs/refs/*   reflog lines: old/new sha, name <email>, epoch + TZ offset, action
  * HEAD, refs/*, packed-refs   branch and tag names
  * objects/xx/yyyy   loose objects (zlib) — commit and tag objects give author / committer /
                      tagger name, e-mail, epoch and TZ offset, plus the message
  * objects/pack/*.pack   listed and counted; commit/tag objects that are stored whole (not
                      deltified) are read by a sequential stdlib walk under a size cap

Beside the repository it reads manifest files that carry the ORIGINAL project's identity:
go.mod `module`, package.json name/repository/author, composer.json, pyproject.toml / setup.cfg,
Cargo.toml, .npmrc registry URLs, .gitmodules URLs.

RULE 5: every identity row is a LEAD (rung 'lead'). A committer string is self-asserted —
anyone can commit as anyone — and a module path names a project, not its operator. Nothing here
becomes a KB edge; corroborate (registrant, payment, platform record) before attribution.
Stdlib only; never raises from analyze().

Usage:
  bp_git.py <archive.zip|.tar|.tgz|DIR> [--pretty]
"""
import argparse
import datetime as _dt
import json
import os
import re
import hashlib
import struct
import sys
import zlib
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bp_refs  # noqa: E402
import bp_archive_time  # noqa: E402 — MemberSource (zip / tar / directory reader)

_FALLBACK = {
    "git": {"max_objects": 5000, "max_commits": 100, "max_pack_bytes": 32 << 20,
            "max_pack_objects": 50000, "max_object_bytes": 1 << 20, "max_reflog_lines": 2000,
            "max_identities": 100, "max_module_files": 100},
    "module_files": {"go.mod": "go", "package.json": "npm", "composer.json": "composer",
                     "pyproject.toml": "python", "setup.cfg": "python", "Cargo.toml": "cargo",
                     ".npmrc": "npm-registry", ".gitmodules": "git-submodule"},
    "module_skip_dirs": ["node_modules", "vendor"],
}
_REF = bp_refs.load_ref(bp_refs.ref_path(__file__, "leak_forensics.json"), _FALLBACK)
_G = {**_FALLBACK["git"], **(_REF.get("git") or {})}
_MODULE_FILES = dict(_REF.get("module_files") or _FALLBACK["module_files"])
_SKIP_DIRS = {str(d) for d in _REF.get("module_skip_dirs") or []}

CAVEAT = ("Self-asserted: git author/committer/config strings are typed by whoever commits and "
          "can name anyone. A lead to corroborate, never an attribution on its own.")
_SIG_RE = re.compile(r"^(?P<name>.*?) <(?P<email>[^>]*)> (?P<epoch>-?\d+) (?P<tz>[+-]\d{4})$")
_REFLOG_RE = re.compile(r"^(?P<old>[0-9a-f]{40}) (?P<new>[0-9a-f]{40}) (?P<sig>.*? <[^>]*> -?\d+ [+-]\d{4})"
                        r"(?:\t(?P<msg>.*))?$")
_LOOSE_RE = re.compile(r"(?:^|/)objects/([0-9a-f]{2})/([0-9a-f]{38})$")
_PACK_TYPES = {1: "commit", 2: "tree", 3: "blob", 4: "tag", 6: "ofs_delta", 7: "ref_delta"}


# ----------------------------------------------------------------------------- helpers
def _utc(epoch):
    try:
        return _dt.datetime.fromtimestamp(int(epoch), _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def _sig(s):
    mo = _SIG_RE.match((s or "").strip())
    if not mo:
        return None
    return {"name": mo["name"], "email": mo["email"], "epoch": int(mo["epoch"]), "tz": mo["tz"]}


def _text(b):
    return (b or b"").decode("utf-8", "replace")


def find_git_dirs(names):
    """Repository roots inside a member listing: every '<prefix>.git/' plus bare repositories
    (a prefix holding HEAD + config + objects/ or refs/). Returns sorted prefixes ending in '/'."""
    nameset = set(names)
    dirs = set()                                   # every directory prefix present ('a/b/')
    for n in names:
        i = n.find("/")
        while i != -1:
            dirs.add(n[:i + 1])
            i = n.find("/", i + 1)
    prefixes = set()
    for n in names:
        parts = n.split("/")
        for i, p in enumerate(parts[:-1]):
            if p == ".git":
                prefixes.add("/".join(parts[:i + 1]) + "/")
                break
        if parts[-1] == "HEAD" and "/.git/" not in "/" + n:
            pre = n[:-len("HEAD")]
            if (pre + "config" in nameset and not pre.endswith("logs/")
                    and (pre + "objects/" in dirs or pre + "refs/" in dirs)):
                prefixes.add(pre)
    return sorted(prefixes)


def parse_config(body):
    """Tiny git-config reader: {section_key: {key: [values]}} with 'remote "origin"' style keys."""
    out, sect = {}, None
    for raw in _text(body).splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        mo = re.match(r'^\[\s*([A-Za-z0-9.\-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]', line)
        if mo:
            sect = mo[1].lower() + (f' "{mo[2]}"' if mo[2] is not None else "")
            out.setdefault(sect, {})
            continue
        if sect is None:
            continue
        k, _, v = line.partition("=")
        out[sect].setdefault(k.strip().lower(), []).append(v.strip().strip('"'))
    return out


def parse_commit(body):
    """Commit/tag object body (after the 'type size\\0' header) -> dict."""
    head, _, msg = _text(body).partition("\n\n")
    c = {"parents": []}
    for line in head.split("\n"):
        if line.startswith(" "):          # continuation (gpgsig / mergetag)
            continue
        k, _, v = line.partition(" ")
        if k == "tree":
            c["tree"] = v
        elif k == "parent":
            c["parents"].append(v)
        elif k in ("author", "committer", "tagger"):
            c[k] = _sig(v)
        elif k in ("object", "type", "tag"):
            c["tag_" + k] = v
        elif k in ("gpgsig", "gpgsig-sha256"):
            c["signed"] = True
    c["message"] = msg.strip()[:500]
    return c


def _decompress(data, cap):
    try:
        d = zlib.decompressobj()
        return d.decompress(data, cap)
    except zlib.error:
        return None


def _walk_pack(data, max_objects, max_obj_bytes):
    """Sequentially walk a v2/v3 packfile and yield (type_name, body) for whole commit/tag
    objects. Deltified and other objects are skipped by consuming their zlib stream."""
    if data[:4] != b"PACK" or len(data) < 12:
        return
    _ver, count = struct.unpack(">II", data[4:12])
    pos, end = 12, len(data) - 20
    for _ in range(min(count, max_objects)):
        if pos >= end:
            return
        b = data[pos]
        pos += 1
        typ = (b >> 4) & 7
        while b & 0x80:
            if pos >= end:
                return
            b = data[pos]
            pos += 1
        if typ == 6:                      # ofs_delta: varint negative offset
            b = 0x80
            while b & 0x80:
                if pos >= end:
                    return
                b = data[pos]
                pos += 1
        elif typ == 7:
            pos += 20
        d = zlib.decompressobj()
        keep = typ in (1, 4)
        out = bytearray()
        mv = memoryview(data)
        try:
            while not d.eof and pos < len(data):
                chunk = mv[pos:pos + 65536]
                got = d.decompress(chunk)
                if keep and len(out) <= max_obj_bytes:
                    out += got
                pos += len(chunk) - len(d.unused_data)
                if d.unused_data:
                    break
        except zlib.error:
            return
        if keep:
            yield _PACK_TYPES[typ], bytes(out[:max_obj_bytes])


# ----------------------------------------------------------------------------- per repo
def analyze_repo(src, prefix, ids, budget):
    """Parse one repository rooted at `prefix` (ends in '/'). Mutates the shared identity map
    `ids`; returns the repo block."""
    names = [n for n in src.names() if n.startswith(prefix)]
    rel = {n[len(prefix):]: n for n in names}
    repo = {"path": prefix.rstrip("/") or ".", "bare": not prefix.rstrip("/").endswith(".git"),
            "remotes": [], "refs": {}, "commits": [], "reflog": [], "packs": [],
            "loose_objects": 0}

    def rd(r, cap=None):
        n = rel.get(r)
        return src.read(n, cap) if n else None

    head = rd("HEAD", 4096)
    if head:
        repo["head"] = _text(head).strip()
    cfg = rd("config", 256 * 1024)
    if cfg:
        conf = parse_config(cfg)
        for sect, kv in conf.items():
            if sect.startswith("remote "):
                for u in kv.get("url", []):
                    repo["remotes"].append(_remote(sect[8:-1], u, "config"))
            elif sect.startswith("submodule "):
                for u in kv.get("url", []):
                    repo["remotes"].append(_remote(sect[11:-1], u, "config submodule"))
        user = conf.get("user", {})
        if user.get("name") or user.get("email"):
            _note(ids, (user.get("name") or [""])[-1], (user.get("email") or [""])[-1], "config",
                  None, None, repo["path"])
    for r, full in rel.items():
        if r.startswith("refs/") and not r.endswith("/"):
            v = src.read(full, 256)
            if v:
                repo["refs"][r] = _text(v).strip()[:80]
    packed = rd("packed-refs", 4 << 20)
    for line in _text(packed).splitlines():
        p = line.split(" ", 1)
        if len(p) == 2 and re.fullmatch(r"[0-9a-f]{40,64}", p[0]):
            repo["refs"].setdefault(p[1].strip(), p[0])

    # reflogs
    nlog = 0
    for r, full in sorted(rel.items()):
        if not (r == "logs/HEAD" or r.startswith("logs/refs/")) or r.endswith("/"):
            continue
        for line in _text(src.read(full)).splitlines():
            if nlog >= _G["max_reflog_lines"]:
                break
            mo = _REFLOG_RE.match(line)
            if not mo:
                continue
            s = _sig(mo["sig"])
            if not s:
                continue
            nlog += 1
            _note(ids, s["name"], s["email"], "reflog", s["epoch"], s["tz"], repo["path"])
            if len(repo["reflog"]) < _G["max_commits"]:
                repo["reflog"].append({"log": r, "old": mo["old"], "new": mo["new"],
                                       "name": s["name"], "email": s["email"],
                                       "when_utc": _utc(s["epoch"]), "tz": s["tz"],
                                       "message": (mo["msg"] or "")[:200]})

    seen = set()

    def take(sha, typ, body):
        if sha in seen:
            return
        seen.add(sha)
        c = parse_commit(body)
        for role in ("author", "committer", "tagger"):
            s = c.get(role)
            if s:
                _note(ids, s["name"], s["email"], role, s["epoch"], s["tz"], repo["path"])
        if len(repo["commits"]) < _G["max_commits"]:
            row = {"sha": sha, "type": typ, "tree": c.get("tree"), "parents": c["parents"],
                   "message": c["message"][:200]}
            for role in ("author", "committer", "tagger"):
                s = c.get(role)
                if s:
                    row[role] = {"name": s["name"], "email": s["email"],
                                 "when_utc": _utc(s["epoch"]), "tz": s["tz"]}
            if c.get("tag_tag"):
                row["tag"] = c["tag_tag"]
            if c.get("signed"):
                row["signed"] = True
            repo["commits"].append(row)

    # loose objects: read just the header first, the whole object only for commit/tag
    for r, full in rel.items():
        mo = _LOOSE_RE.search(r)
        if not mo:
            continue
        repo["loose_objects"] += 1
        if repo["loose_objects"] > _G["max_objects"]:
            continue
        data = src.read(full, _G["max_object_bytes"])
        if not data:
            continue
        hdr = _decompress(data, 32)
        if not hdr or not hdr.startswith((b"commit ", b"tag ")):
            continue
        whole = _decompress(data, _G["max_object_bytes"])
        if whole and b"\0" in whole:
            typ, _, body = whole.partition(b"\0")
            take(mo[1] + mo[2], typ.split(b" ")[0].decode(), body)

    # packfiles
    for r, full in sorted(rel.items()):
        if not (r.startswith("objects/pack/") and r.endswith(".pack")):
            continue
        size = next((m["size"] for m in src.members if m["name"] == full), 0)
        pk = {"name": r, "size": size}
        idx = rd(r[:-5] + ".idx", 8 + 256 * 4)
        if idx and idx[:4] == b"\xfftOc" and len(idx) >= 8 + 1024:
            pk["objects"] = struct.unpack(">I", idx[8 + 255 * 4:8 + 256 * 4])[0]
        if size and size <= _G["max_pack_bytes"] and budget[0] > 0:
            data = src.read(full, _G["max_pack_bytes"])
            if data:
                budget[0] -= len(data)
                walked = 0
                for typ, body in _walk_pack(data, _G["max_pack_objects"], _G["max_object_bytes"]):
                    walked += 1
                    sha = hashlib.sha1(f"{typ} {len(body)}\0".encode() + body).hexdigest()
                    take(sha, typ, body)
                pk["walked_commit_tag_objects"] = walked
        else:
            pk["walked"] = False
            pk["reason"] = "pack larger than git.max_pack_bytes" if size else "size unknown"
        repo["packs"].append(pk)
    repo["commits"].sort(key=lambda c: (c.get("committer") or c.get("tagger") or {}).get("when_utc") or "")
    if not repo["reflog"]:
        repo.pop("reflog")
    return repo


def _remote(name, url, source):
    out = {"name": name, "url": url, "source": source, "rung": "lead"}
    mo = re.match(r"^(?:[a-z+]+://)?(?:(?P<user>[^@/:]+)(?::(?P<pw>[^@/]*))?@)?(?P<host>[^/:]+)[:/](?P<path>.+?)(?:\.git)?/?$",
                  url.strip())
    if mo:
        out["host"] = mo["host"]
        out["path"] = mo["path"]
        if mo["user"] and mo["user"] not in ("git",):
            out["url_user"] = mo["user"]
        if mo["pw"]:
            out["embedded_credential"] = True
    return out


def _note(ids, name, email, role, epoch, tz, repo):
    if not (name or email):
        return
    key = ((name or "").strip(), (email or "").strip().lower())
    row = ids.get(key)
    if row is None:
        if len(ids) >= _G["max_identities"]:
            return
        row = ids[key] = {"name": key[0], "email": key[1], "roles": set(), "count": 0,
                          "first_epoch": None, "last_epoch": None, "tz": Counter(), "repos": set()}
    row["roles"].add(role)
    row["count"] += 1
    row["repos"].add(repo)
    if epoch is not None:
        row["first_epoch"] = epoch if row["first_epoch"] is None else min(row["first_epoch"], epoch)
        row["last_epoch"] = epoch if row["last_epoch"] is None else max(row["last_epoch"], epoch)
    if tz:
        row["tz"][tz] += 1


# ----------------------------------------------------------------------------- module identifiers
def _module_rows(src):
    rows = []
    for m in src.members:
        if len(rows) >= _G["max_module_files"]:
            break
        if m["is_dir"]:
            continue
        parts = m["name"].split("/")
        eco = _MODULE_FILES.get(parts[-1])
        if not eco or any(p in _SKIP_DIRS or p == ".git" for p in parts[:-1]):
            continue
        body = _text(src.read(m["name"], 512 * 1024))
        row = _parse_manifest(eco, parts[-1], body)
        if row:
            row.update({"file": m["name"], "ecosystem": eco, "rung": "lead"})
            rows.append(row)
    return rows


def _toml_or_ini(body, keys):
    out = {}
    for k in keys:
        mo = re.search(rf'(?m)^\s*{re.escape(k)}\s*[=:]\s*(.+?)\s*$', body)
        if mo:
            out[k] = mo[1].strip().strip('"\'')
    return out


def _parse_manifest(eco, base, body):
    if eco == "go":
        mo = re.search(r"(?m)^\s*module\s+(\S+)", body)
        return {"name": mo[1].strip('"')} if mo else None
    if base in ("package.json", "composer.json"):
        try:
            doc = json.loads(body)
        except ValueError:
            return None
        if not isinstance(doc, dict):
            return None
        out = {}
        if isinstance(doc.get("name"), str):
            out["name"] = doc["name"]
        repo = doc.get("repository")
        if isinstance(repo, dict):
            repo = repo.get("url")
        if isinstance(repo, str):
            out["repository"] = repo
        for k in ("homepage",):
            if isinstance(doc.get(k), str):
                out[k] = doc[k]
        people = []
        for k in ("author", "authors", "contributors", "maintainers"):
            v = doc.get(k)
            for p in (v if isinstance(v, list) else [v] if v else []):
                if isinstance(p, str):
                    people.append(p)
                elif isinstance(p, dict):
                    people.append(" ".join(str(p[x]) for x in ("name", "email") if p.get(x)))
        if people:
            out["authors"] = people[:20]
        return out or None
    if eco == "python" or eco == "cargo":
        kv = _toml_or_ini(body, ("name", "author", "author_email", "url", "homepage", "repository"))
        mo = re.search(r"(?ms)^\s*authors\s*=\s*\[(.*?)\]", body)
        if mo:
            kv["authors"] = re.findall(r'"([^"]+)"|\{[^}]*name\s*=\s*"([^"]+)"', mo[1])
            kv["authors"] = [a if isinstance(a, str) else next(x for x in a if x) for a in kv["authors"]][:20]
        return kv or None
    if eco == "npm-registry":
        urls = re.findall(r"(?m)^\s*(?:@[\w\-.]+:)?registry\s*=\s*(\S+)", body)
        scopes = re.findall(r"(?m)^\s*(@[\w\-.]+):registry", body)
        hosts = re.findall(r"(?m)^\s*//([^/:\s]+)[^:\s]*:_", body)
        out = {}
        if urls:
            out["registries"] = sorted(set(urls))
        if scopes:
            out["scopes"] = sorted(set(scopes))
        if hosts:
            out["auth_hosts"] = sorted(set(hosts))
        return out or None
    if eco == "git-submodule":
        urls = re.findall(r"(?m)^\s*url\s*=\s*(\S+)", body)
        return {"urls": urls[:50]} if urls else None
    return None


# ----------------------------------------------------------------------------- entry points
def analyze_source(src):
    """Embedded-repo + module-identifier forensics over a MemberSource. {} when nothing found."""
    if src is None or not src.members:
        return {}
    names = src.names()
    ids = {}
    budget = [int(_G["max_pack_bytes"]) * 4]
    repos = [analyze_repo(src, p, ids, budget) for p in find_git_dirs(names)]
    gitfiles = [m["name"] for m in src.members
                if not m["is_dir"] and m["name"].split("/")[-1] == ".git"]
    pointers = []
    for n in gitfiles[:20]:
        body = _text(src.read(n, 4096)).strip()
        if body.startswith("gitdir:"):
            pointers.append({"file": n, "gitdir": body[7:].strip(), "rung": "lead"})
    modules = _module_rows(src)

    identities, tz_hist = [], Counter()
    for row in sorted(ids.values(), key=lambda r: (-r["count"], r["email"])):
        tz_hist.update(row["tz"])
        identities.append({
            "name": row["name"], "email": row["email"], "roles": sorted(row["roles"]),
            "count": row["count"],
            "first_seen_utc": _utc(row["first_epoch"]) if row["first_epoch"] is not None else None,
            "last_seen_utc": _utc(row["last_epoch"]) if row["last_epoch"] is not None else None,
            "tz_offsets": dict(row["tz"].most_common()), "repos": sorted(row["repos"]),
            "rung": "lead", "caveat": CAVEAT})
    remotes = [dict(r, repo=repo["path"]) for repo in repos for r in repo["remotes"]]
    commits = [dict(c, repo=repo["path"]) for repo in repos for c in repo["commits"]]
    for repo in repos:
        repo.pop("commits", None)
        repo.pop("remotes", None)
    if not (repos or pointers or modules):
        return {}
    out = {"repos": repos, "identities": identities, "remotes": remotes,
           "module_paths": modules, "commits": commits[:_G["max_commits"]],
           "tz_histogram": dict(tz_hist.most_common()),
           "rung": "lead", "caveat": CAVEAT}
    if pointers:
        out["gitdir_pointers"] = pointers
    return {k: v for k, v in out.items() if v or k in ("rung", "caveat")}


def analyze(raw=None, path=None):
    """Tri-state: dict | {} | {'error': ...}."""
    try:
        return analyze_source(bp_archive_time.open_source(raw=raw, path=path))
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"}


def main():
    ap = argparse.ArgumentParser(description="Embedded .git + project-identifier forensics.")
    ap.add_argument("target", help="archive file or directory")
    ap.add_argument("--pretty", action="store_true")
    a = ap.parse_args()
    res = analyze(path=a.target)
    print(json.dumps(res, indent=2 if a.pretty else None, ensure_ascii=False))
    return 0 if not res.get("error") else 2


if __name__ == "__main__":
    sys.exit(main())
