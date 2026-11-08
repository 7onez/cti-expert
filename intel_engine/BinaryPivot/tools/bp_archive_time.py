#!/usr/bin/env python3
"""
bp_archive_time.py — leak-archive TIMESTAMP forensics, plus the member-source reader the other
leaked-source layers (bp_git.py, bp_keys.py) share.

A leaked source archive or a seized directory carries a second story beside its content: WHEN
and HOW it was assembled. This layer reads member times and reports:

  * bulk-copy clusters — many files sharing one second: a copy/extraction step erased the
    original authoring times before packaging;
  * directory-only seconds — times carried only by directory entries: usually the packaging or
    extraction moment;
  * sequential generation runs — files written one after another (a build, a generator, an
    export script);
  * stripped timestamps — DOS 1980-01-01 zip entries / tar mtime 0;
  * future / implausible dates;
  * the PACKER'S UTC OFFSET — a zip stores DOS local time (no zone) and, when the packer added
    a UT (0x5455) or NTFS (0x000a) extra field, the same moment in UTC; local − UTC is the
    packer's clock offset;
  * author-metadata presence — home-directory usernames / UNC hostnames in member paths or small
    text members, tar owner names, and the zip host OS.

All of it is a FACT or a LEAD (rung 'lead'): a clock offset suggests a region, a home path names
an account — neither names an operator on its own. Stdlib only; never raises from analyze().

Usage:
  bp_archive_time.py <archive.zip|.tar|.tgz|DIR> [--pretty]
"""
import argparse
import datetime as _dt
import io
import json
import os
import re
import struct
import sys
import tarfile
import zipfile
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bp_refs  # noqa: E402

_FALLBACK = {
    "source_limits": {"max_members": 50000, "max_member_bytes": 4 << 20,
                      "max_total_bytes": 64 << 20, "max_walk_depth": 20},
    "archive_time": {"bulk_min_files": 20, "bulk_min_fraction": 0.3, "bulk_floor": 5,
                     "seq_min_files": 10, "seq_max_gap_seconds": 2,
                     "implausible_before_year": 1990, "future_slack_seconds": 86400,
                     "max_events": 60, "offset_round_minutes": 15, "max_author_hits": 40,
                     "content_scan_max_bytes": 262144},
    "author_path_patterns": [r"/home/([a-z_][a-z0-9_.\-]{0,31})/", r"/Users/([A-Za-z0-9_.\-]{1,64})/"],
    "author_ignore_users": ["root", "runner", "user"],
}
_REF = bp_refs.load_ref(bp_refs.ref_path(__file__, "leak_forensics.json"), _FALLBACK)
_LIM = {**_FALLBACK["source_limits"], **(_REF.get("source_limits") or {})}
_T = {**_FALLBACK["archive_time"], **(_REF.get("archive_time") or {})}
_AUTHOR_RES = []
for _p in _REF.get("author_path_patterns") or []:
    try:
        _AUTHOR_RES.append(re.compile(_p, re.I))
    except re.error as _e:
        sys.stderr.write(f"[bp_archive_time] bad author_path_patterns regex {_p!r}: {_e}\n")
_IGNORE_USERS = {str(u).lower() for u in _REF.get("author_ignore_users") or []}

CAVEAT = ("Timestamps are set by whoever packed or copied the files and are trivially forged; "
          "they describe the packaging environment, not an identity. Corroborate before use.")
_ZIP_HOST_OS = {0: "MS-DOS/Windows (FAT)", 3: "Unix", 7: "Macintosh", 10: "Windows NTFS",
                11: "MVS", 19: "OS/X (Darwin)"}
_TEXTISH = re.compile(r"\.(txt|md|json|ya?ml|xml|ini|cfg|conf|properties|env|js|ts|py|go|php|rb|"
                      r"java|kt|cs|sh|bat|ps1|toml|lock|log|html?|plist|gradle|sln|csproj|iml|"
                      r"code-workspace)$|(^|/)(\.[a-z]+rc|Makefile|Dockerfile)$", re.I)


# ----------------------------------------------------------------------------- member source
class MemberSource:
    """A uniform view over a zip, a tar(.gz/.bz2/.xz) or a local directory.

    members: [{name, size, is_dir, mtime, dos_local, utc_extra, owner, host_os}]
      name       '/'-separated path inside the container
      mtime      epoch seconds UTC when the format gives UTC (tar, directory, zip UT/NTFS)
      dos_local  zip only: 'YYYY-MM-DDTHH:MM:SS' DOS local time (no zone)
      owner      tar only: 'uname:gname' when present
    read(name) -> bytes | None, honouring the per-member and total read budget."""

    def __init__(self, kind):
        self.kind = kind
        self.members = []
        self.truncated = 0          # members beyond max_members (counted, not listed)
        self.budget = int(_LIM["max_total_bytes"])
        self._reader = None

    def names(self):
        return [m["name"] for m in self.members]

    def read(self, name, cap=None):
        cap = int(cap) if cap else int(_LIM["max_member_bytes"])
        if self.budget <= 0 or self._reader is None:
            return None
        try:
            data = self._reader(name, min(cap, self.budget))
        except Exception:  # noqa: BLE001 — a damaged member is skipped, never fatal
            return None
        if data is not None:
            self.budget -= len(data)
        return data

    # -- constructors ------------------------------------------------------------------
    @classmethod
    def from_zip(cls, raw):
        src = cls("zip")
        zf = zipfile.ZipFile(io.BytesIO(raw))
        for i, info in enumerate(zf.infolist()):
            if i >= _LIM["max_members"]:
                src.truncated += 1
                continue
            src.members.append({
                "name": info.filename, "size": info.file_size, "is_dir": info.is_dir(),
                "dos_local": "%04d-%02d-%02dT%02d:%02d:%02d" % info.date_time,
                "utc_extra": _zip_extra_utc(info.extra),
                "host_os": info.create_system,
            })
            src.members[-1]["mtime"] = src.members[-1]["utc_extra"]

        def _read(name, cap):
            with zf.open(name) as fh:
                return fh.read(cap)
        src._reader = _read
        return src

    @classmethod
    def from_tar(cls, raw):
        src = cls("tar")
        tf = tarfile.open(fileobj=io.BytesIO(raw), mode="r:*")
        index = {}
        for i, ti in enumerate(tf):
            if i >= _LIM["max_members"]:
                src.truncated += 1
                continue
            if not (ti.isfile() or ti.isdir()):
                continue
            owner = ":".join(x for x in (ti.uname, ti.gname) if x) or None
            name = ti.name.lstrip("./") if ti.name not in (".", "./") else "."
            src.members.append({"name": name + ("/" if ti.isdir() and not name.endswith("/") else ""),
                                "size": ti.size, "is_dir": ti.isdir(), "mtime": int(ti.mtime),
                                "owner": owner, "uid": ti.uid})
            index[src.members[-1]["name"]] = ti

        def _read(name, cap):
            ti = index.get(name)
            fh = tf.extractfile(ti) if ti is not None and ti.isfile() else None
            return fh.read(cap) if fh else None
        src._reader = _read
        return src

    @classmethod
    def from_dir(cls, root):
        src = cls("dir")
        root = os.path.abspath(root)
        base_depth = root.rstrip(os.sep).count(os.sep)
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if dirpath.count(os.sep) - base_depth >= _LIM["max_walk_depth"]:
                dirnames[:] = []
            rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
            for d in sorted(dirnames):
                _add_stat(src, os.path.join(dirpath, d), _join(rel_dir, d) + "/", True)
            for f in sorted(filenames):
                _add_stat(src, os.path.join(dirpath, f), _join(rel_dir, f), False)

        def _read(name, cap):
            p = os.path.join(root, *name.split("/"))
            if os.path.islink(p) or not os.path.isfile(p):
                return None
            with open(p, "rb") as fh:
                return fh.read(cap)
        src._reader = _read
        return src


def _join(rel_dir, leaf):
    return leaf if rel_dir in (".", "") else f"{rel_dir}/{leaf}"


def _add_stat(src, path, name, is_dir):
    if len(src.members) >= _LIM["max_members"]:
        src.truncated += 1
        return
    try:
        st = os.lstat(path)
    except OSError:
        return
    if not is_dir and not os.path.isfile(path):
        return
    src.members.append({"name": name, "size": 0 if is_dir else st.st_size, "is_dir": is_dir,
                        "mtime": int(st.st_mtime)})


def open_source(raw=None, path=None):
    """MemberSource for a directory path, or for archive bytes (zip first, then any tar).
    Returns None when the input is neither."""
    if path and os.path.isdir(path):
        return MemberSource.from_dir(path)
    if raw is None and path:
        with open(path, "rb") as fh:
            raw = fh.read()
    if not raw:
        return None
    if raw[:2] == b"PK":
        try:
            return MemberSource.from_zip(raw)
        except Exception:  # noqa: BLE001
            return None
    try:
        return MemberSource.from_tar(raw)
    except Exception:  # noqa: BLE001
        return None


def _zip_extra_utc(extra):
    """UTC mtime from a zip extra block: UT 0x5455 (unix seconds) or NTFS 0x000a (FILETIME)."""
    off, ut, ntfs = 0, None, None
    while off + 4 <= len(extra or b""):
        hid, ln = struct.unpack_from("<HH", extra, off)
        body = extra[off + 4:off + 4 + ln]
        if hid == 0x5455 and len(body) >= 5 and body[0] & 1:
            ut = struct.unpack_from("<i", body, 1)[0]
        elif hid == 0x000A and len(body) >= 32:
            p = 4
            while p + 4 <= len(body):
                tag, sz = struct.unpack_from("<HH", body, p)
                if tag == 1 and sz >= 24 and p + 12 <= len(body):
                    ft = struct.unpack_from("<Q", body, p + 4)[0]
                    if ft:
                        ntfs = int(ft // 10_000_000 - 11_644_473_600)
                    break
                p += 4 + sz
        off += 4 + ln
    return ut if ut is not None else ntfs


# ----------------------------------------------------------------------------- analysis
def _iso(epoch):
    return _dt.datetime.fromtimestamp(epoch, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fmt_offset(minutes):
    sign = "+" if minutes >= 0 else "-"
    m = abs(minutes)
    return f"{sign}{m // 60:02d}:{m % 60:02d}"


def _member_clock(m, kind):
    """(sort_key_seconds, label, clock) for one member, or None when stripped/absent.
    Zip without an extra field only has DOS local time: it is ordered on its naive value and
    labelled clock='local (packer zone, unknown)'."""
    if m.get("mtime") is not None and not (kind == "tar" and m["mtime"] == 0):
        return int(m["mtime"]), _iso(m["mtime"]), "utc"
    dl = m.get("dos_local")
    if dl and not dl.startswith("1980-01-01T00:00"):
        naive = _dt.datetime.strptime(dl, "%Y-%m-%dT%H:%M:%S")
        return int(naive.replace(tzinfo=_dt.timezone.utc).timestamp()), dl, "local"
    return None


def _is_stripped(m, kind):
    if kind == "zip":
        return (m.get("dos_local") or "").startswith("1980-01-01T00:00") and not m.get("utc_extra")
    return m.get("mtime") in (None, 0)


def infer_utc_offset(members):
    """Packer clock offset from zip members carrying both DOS local time and UT/NTFS UTC."""
    step = max(1, int(_T["offset_round_minutes"])) * 60
    votes = Counter()
    for m in members:
        dl, utc = m.get("dos_local"), m.get("utc_extra")
        if not dl or utc is None or dl.startswith("1980-01-01T00:00"):
            continue
        naive = _dt.datetime.strptime(dl, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=_dt.timezone.utc)
        diff = naive.timestamp() - utc
        if abs(diff) > 15 * 3600:
            continue
        votes[int(round(diff / step) * step) // 60] += 1
    if not votes:
        return None
    best, n = votes.most_common(1)[0]
    total = sum(votes.values())
    return {"offset": _fmt_offset(best), "minutes": best, "agreeing": n, "compared": total,
            "basis": f"{total} zip member(s) carry both DOS local time and a UT/NTFS UTC time; "
                     f"offset = DOS local - UTC (mode, rounded to {_T['offset_round_minutes']} min)",
            "alternatives": {_fmt_offset(k): v for k, v in votes.most_common()[1:5]},
            "rung": "lead",
            "caveat": "The packer machine's clock zone at packing time — consistent with a region, "
                      "not proof of one (VPS, travel and deliberate zone changes all shift it)."}


def _author_metadata(src):
    hits, seen = [], set()
    max_hits = int(_T["max_author_hits"])

    def note(where, kind, value, sample):
        key = (kind, value.lower())
        if value.lower() in _IGNORE_USERS or key in seen or len(hits) >= max_hits:
            return
        seen.add(key)
        hits.append({"kind": kind, "value": value, "where": where, "sample": sample[:160],
                     "rung": "lead"})

    for m in src.members:
        for rx in _AUTHOR_RES:
            for mo in rx.finditer("/" + m["name"]):
                note(m["name"], "path_user", mo.group(1), m["name"])
    owners = Counter(m["owner"] for m in src.members if m.get("owner"))
    budget = int(_T["content_scan_max_bytes"])
    for m in src.members:
        if budget <= 0 or len(hits) >= max_hits:
            break
        if m["is_dir"] or not m["size"] or m["size"] > budget or not _TEXTISH.search(m["name"]):
            continue
        if "/.git/objects/" in "/" + m["name"]:
            continue
        data = src.read(m["name"], cap=min(m["size"], budget))
        if not data:
            continue
        budget -= len(data)
        text = data.decode("utf-8", "ignore")
        for rx in _AUTHOR_RES:
            for mo in rx.finditer(text):
                s = max(0, mo.start() - 20)
                note(m["name"], "content_user", mo.group(1), text[s:mo.end() + 40].replace("\n", " "))
    host_os = Counter(_ZIP_HOST_OS.get(m["host_os"], str(m["host_os"]))
                      for m in src.members if m.get("host_os") is not None)
    out = {"present": bool(hits or [o for o in owners if o.split(":")[0].lower() not in _IGNORE_USERS])}
    if hits:
        out["hits"] = hits
    if owners:
        out["tar_owners"] = dict(owners.most_common(10))
    if host_os:
        out["zip_host_os"] = dict(host_os.most_common())
    return out


def analyze_source(src):
    """Timestamp forensics over a MemberSource. Returns {} when there is nothing to say."""
    if src is None or not src.members:
        return {}
    kind = src.kind
    files = [m for m in src.members if not m["is_dir"]]
    dirs = [m for m in src.members if m["is_dir"]]
    stripped = sum(1 for m in src.members if _is_stripped(m, kind))
    now = _dt.datetime.now(_dt.timezone.utc).timestamp()
    floor_year = int(_T["implausible_before_year"])

    fclock = [c for c in (_member_clock(m, kind) for m in files) if c]
    dclock = [c for c in (_member_clock(m, kind) for m in dirs) if c]
    clock = "utc" if all(c[2] == "utc" for c in fclock + dclock) else "local"
    if kind == "zip" and clock == "local" and any(c[2] == "utc" for c in fclock):
        clock = "mixed"
    gran = 2 if kind == "zip" and clock != "utc" else 1    # DOS time has 2-second resolution

    def bucket(sec):
        return sec - (sec % gran)

    fhist = Counter(bucket(c[0]) for c in fclock)
    where = {}                                     # second -> Counter of top-2 path components
    for m in files:
        c = _member_clock(m, kind)
        if c:
            where.setdefault(bucket(c[0]), Counter())["/".join(m["name"].split("/")[:2])] += 1
    label = {}
    for c in fclock + dclock:
        label.setdefault(bucket(c[0]), c[1])
    dhist = Counter(bucket(c[0]) for c in dclock)

    events, judgments = [], []
    nfiles = len(fclock)
    bulk_secs = set()
    for sec, n in fhist.most_common():
        if n >= int(_T["bulk_min_files"]) or (
                nfiles and n >= int(_T["bulk_floor"]) and n / nfiles >= float(_T["bulk_min_fraction"])):
            bulk_secs.add(sec)
            pct = round(100.0 * n / nfiles, 1) if nfiles else 0
            top = dict(where.get(sec, Counter()).most_common(3))
            events.append({"sec": sec, "when": label[sec], "count": n, "type": "bulk_copy",
                           "what": f"{n} files ({pct}%) share one timestamp — bulk copy/extraction",
                           "top_dirs": top})
            judgments.append(
                f"{'Highly likely' if pct >= 50 or n >= 100 else 'Likely'}: {n} files ({pct}%) were "
                f"written in the same second ({label[sec]}) — a bulk copy or extraction step reset "
                f"their times; original authoring times for those files are probably lost "
                f"(mostly under {', '.join(top) or '?'}).")

    for sec, n in dhist.items():
        if sec not in fhist:
            events.append({"sec": sec, "when": label[sec], "count": n, "type": "directory_only",
                           "what": f"{n} directory entr{'y' if n == 1 else 'ies'} only — "
                                   f"probable packaging/extraction time"})
    dir_only = [e for e in events if e["type"] == "directory_only"]
    if dir_only:
        last = max(dir_only, key=lambda e: e["sec"])
        judgments.append(f"Probably: directory-only timestamp {last['when']} marks when the tree "
                         f"was assembled or packed (no file carries that time).")

    # sequential generation runs over the non-bulk distinct seconds
    secs = sorted(s for s in fhist if s not in bulk_secs)
    gap = max(int(_T["seq_max_gap_seconds"]), gran)
    run = []
    for s in secs + [None]:
        if s is not None and (not run or s - run[-1] <= gap):
            run.append(s)
            continue
        if len(run) >= 2:
            n = sum(fhist[x] for x in run)
            if n >= int(_T["seq_min_files"]):
                events.append({"sec": run[0], "when": label[run[0]], "until": label[run[-1]],
                               "count": n, "type": "sequential_run",
                               "what": f"{n} files written one after another over "
                                       f"{run[-1] - run[0] + gran}s — generator/build/export run"})
                judgments.append(f"Likely: {n} files written sequentially between {label[run[0]]} "
                                 f"and {label[run[-1]]} — a scripted generation or build step.")
        run = [s] if s is not None else []

    weird, weird_secs = [], []
    for m in src.members:
        c = _member_clock(m, kind)
        if not c:
            continue
        year = int(c[1][:4])
        if c[0] > now + int(_T["future_slack_seconds"]):
            weird.append({"name": m["name"], "when": c[1], "why": "future"})
        elif year < floor_year:
            weird.append({"name": m["name"], "when": c[1], "why": f"before {floor_year}"})
        else:
            continue
        weird_secs.append((c[0], c[1]))
    if weird:
        sec, when = min(weird_secs)
        events.append({"sec": sec, "when": when, "count": len(weird),
                       "type": "implausible", "what": "future or implausibly early timestamps"})
        judgments.append(f"Possibly manipulated: {len(weird)} member(s) carry future or pre-"
                         f"{floor_year} times — a wrong packer clock or deliberate tampering.")

    if fclock:
        first, last = min(fclock), max(fclock)
        events.append({"sec": first[0], "when": first[1], "count": 1, "type": "earliest",
                       "what": "earliest file time"})
        events.append({"sec": last[0], "when": last[1], "count": 1, "type": "latest",
                       "what": "latest file time"})

    if stripped:
        judgments.append(f"{'Almost certainly' if stripped == len(src.members) else 'Likely'} "
                         f"deliberate or tool-driven: {stripped} member(s) carry no real timestamp "
                         f"(DOS 1980-01-01 / epoch 0) — reproducible build or sanitised packing.")

    offset = infer_utc_offset(src.members) if kind == "zip" else None
    if offset:
        judgments.append(f"Likely: the packer's clock ran at UTC{offset['offset']} "
                         f"({offset['agreeing']}/{offset['compared']} members agree) — a region "
                         f"hint, not an identity.")
    elif kind == "zip" and clock != "utc":
        judgments.append("Unknown zone: zip times are DOS local time with no UTC extra field, so "
                         "the packer's offset cannot be derived from this archive alone.")

    author = _author_metadata(src)
    if author.get("present"):
        judgments.append("Author metadata present: member paths/contents or tar headers leak "
                         "account or host names (see author_metadata) — leads only.")

    events.sort(key=lambda e: e["sec"])
    for e in events:
        e.pop("sec", None)
    out = {
        "source_kind": kind, "clock": clock, "granularity_seconds": gran,
        "members": len(src.members), "files": len(files), "directories": len(dirs),
        "events": events[:int(_T["max_events"])],
        "inferred_utc_offset": offset,
        "stripped_timestamps": stripped,
        "author_metadata": author,
        "judgments": judgments,
        "rung": "lead", "caveat": CAVEAT,
    }
    if weird:
        out["implausible"] = weird[:40]
    if src.truncated:
        out["members_not_listed"] = src.truncated
    if not (events or stripped or offset or author.get("present")):
        return {}
    return out


def analyze(raw=None, path=None):
    """Tri-state: dict of findings | {} when nothing | {'error': ...} on an unreadable input."""
    try:
        return analyze_source(open_source(raw=raw, path=path))
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"}


def main():
    ap = argparse.ArgumentParser(description="Leak-archive timestamp forensics (zip / tar / directory).")
    ap.add_argument("target", help="archive file or directory")
    ap.add_argument("--pretty", action="store_true")
    a = ap.parse_args()
    res = analyze(path=a.target)
    print(json.dumps(res, indent=2 if a.pretty else None, ensure_ascii=False))
    return 0 if not res.get("error") else 2


if __name__ == "__main__":
    sys.exit(main())
