#!/usr/bin/env python3
"""wp_custody — chain of custody for stored evidence (handbook/collection-preservation.md §5, §6).

A hashed capture proves what was stored. It does not say WHO collected it, from WHICH egress, as
WHICH persona, against a clock in WHAT state, nor what happened to it afterwards. This module adds
those records, stdlib-only and offline:

  - `collection_context()` — collector, persona, egress IP (or null plus the reason) and the local
    clock-sync state, merged into every capture and screenshot manifest (¶155(g));
  - `append()` — one line per custody event in the APPEND-ONLY `cases/<case>/evidence/custody.jsonl`.
    Each line carries the sha256 of the line before it, so an edited, removed or reordered line
    breaks the chain and `check_log()` says where (¶167). The chain alone cannot see the END of the
    log being cut off or its last line being rewritten: every append therefore returns the HEAD
    (sha256 of the last line plus the entry count), verify / fixity / manifests record it, and
    `check_log(expected_head=…)` compares the log against a head recorded earlier. A torn line is
    terminated before the next append and reported distinctly, without discarding any bytes;
  - `seal()` — make an original read-only once it has verified (¶168). Permission bits are not
    content: every manifest digest still matches after the chmod. A failing chmod (read-only
    mount, EPERM) raises `SealError`, which callers report as `seal_status: failed`, never tampering;
  - `working_copy()` — copy an original into `evidence/work/`, check the copy byte-for-byte, log it,
    and leave the original untouched (¶169);
  - `sample()` — the seeded random draw a fixity run re-hashes (¶172). The seed is returned, so any
    run can be reproduced exactly.

The clock-sync state is read from LOCAL commands only (`references/custody.json` → `clock_sync`);
no network time service is ever contacted. Anything that cannot be read is `unknown`, never a guess.
"""
import datetime
from contextlib import contextmanager, ExitStack
import getpass
import hashlib
import ipaddress
import json
import os
import random
import re
import secrets
import shutil
import subprocess
import stat
import sys
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wp_refs import load_ref, ref_path  # noqa: E402 — reference DATA lives in references/*.json

try:
    import fcntl                       # POSIX: serialise appenders so the hash chain stays linear
except ImportError:                    # pragma: no cover — Windows: single-writer assumption
    fcntl = None

# The fallback knows the minimum: where the log lives and the five actions the handbook names. Its
# clock list is EMPTY on purpose — a broken data file must yield `unknown`, not a guessed state —
# and its hand-recordable action list is the smaller one.
_CUSTODY_FALLBACK = {
    "layout": {"evidence_dir": "evidence", "log_filename": "custody.jsonl", "work_dir": "work",
               "salt_filename": "collector.salt"},
    "actions": ["capture", "verify", "copy", "export", "transfer"],
    "manual_actions": ["export", "transfer"],
    "fixity": {"default_sample": 5},
    "identity": {"collector_env": "CTI_COLLECTOR", "persona_env": "CTI_PERSONA",
                 "egress_env": "CTI_EGRESS_IP"},
    "clock_sync": [],
}
_REFS = load_ref(ref_path(__file__, "custody.json"), _CUSTODY_FALLBACK)
LAYOUT = _REFS["layout"]
ACTIONS = list(_REFS["actions"])
# capture / verify / copy are written by the tools that did the work, never by hand: a manual
# `capture` line would give fixity a digest nobody computed. Code, not data, enforces that.
_AUTOMATIC = ("capture", "verify", "copy")
MANUAL_ACTIONS = [a for a in _REFS["manual_actions"] if a in ACTIONS and a not in _AUTOMATIC]
FIXITY = _REFS["fixity"]
IDENTITY = _REFS["identity"]
CLOCK_COMMANDS = list(_REFS["clock_sync"])

GENESIS = "0" * 64                     # `prev` of the first line in a log
_PREV_RE = re.compile(rb'"prev":\s*"([0-9a-f]{64})"')
_HEAD_RE = re.compile(r"^([0-9a-f]{64}):(\d+)$")

_FILE_RO, _DIR_RO = 0o444, 0o555
_FILE_RW, _DIR_RW = 0o644, 0o755


def utc_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@contextmanager
def pinned(path: str, directory: bool = False):
    """Pin a non-link inode. POSIX opens every component relative to a no-follow directory fd.
    Without O_NOFOLLOW/dir_fd (notably Windows), lstat and inode checks are the fallback; they
    refuse observed links but cannot provide the same atomic anti-reparse guarantee."""
    path = os.path.abspath(path)
    fds = []
    try:
        if os.open in os.supports_dir_fd:
            parent = os.open(os.path.sep, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            fds.append(parent)
            parts = path.split(os.sep)[1:]
            for i, name in enumerate(parts):
                before = os.stat(name, dir_fd=parent, follow_symlinks=False)
                is_dir = i < len(parts) - 1 or directory
                if stat.S_ISLNK(before.st_mode) or not (
                        stat.S_ISDIR(before.st_mode) if is_dir else stat.S_ISREG(before.st_mode)):
                    raise ValueError(f"not a non-link {'directory' if is_dir else 'file'}: {path}")
                fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                             | (getattr(os, "O_DIRECTORY", 0) if is_dir else 0), dir_fd=parent)
                fds.append(fd)
                after = os.fstat(fd)
                if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                    raise ValueError(f"replaced during open: {path}")
                # Only the final inode needs to remain pinned after the next component is open.
                os.close(fds.pop(-2))
                parent = fd
        else:  # Windows: inspect every component, never silently follow an observed link.
            drive, tail = os.path.splitdrive(path)
            current = drive + os.sep
            for part in tail.strip(os.sep).split(os.sep):
                current = os.path.join(current, part)
                if stat.S_ISLNK(os.lstat(current).st_mode):
                    raise ValueError(f"symlink: {current}")
            before = os.lstat(path)
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            fds.append(fd)
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise ValueError(f"replaced during open: {path}")
        if not directory and os.fstat(fd).st_nlink != 1:
            raise ValueError(f"shared hard-linked evidence: {path}")
        yield fd
    finally:
        for fd in reversed(fds):
            os.close(fd)


def inode_state(s):
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def fd_sha256(fd: int) -> str:
    h = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    for chunk in iter(lambda: os.read(fd, 1 << 20), b""):
        h.update(chunk)
    return h.hexdigest()


def file_sha256(path: str) -> str:
    with pinned(path) as fd:
        return fd_sha256(fd)


# --------------------------------------------------------------------------- collection context
def _case_salt(evidence_dir: str):
    """The case's random pseudonym salt (created once, never rewritten), or None when there is no
    case store or it cannot be written. Created by hard-linking a finished temp file, so a
    concurrent reader never sees an empty salt."""
    if not evidence_dir:
        return None
    path = os.path.join(evidence_dir, LAYOUT.get("salt_filename") or "collector.salt")
    for _ in range(2):
        try:
            with open(path, encoding="ascii") as fh:
                s = fh.read().strip()
            if s:
                return s
        except (OSError, UnicodeError):
            pass
        tmp = f"{path}.{os.getpid()}.{secrets.token_hex(4)}"
        try:
            os.makedirs(evidence_dir, exist_ok=True)
            with open(tmp, "w", encoding="ascii") as fh:
                fh.write(secrets.token_hex(16) + "\n")
            os.chmod(tmp, _FILE_RO)
            os.link(tmp, path)
        except FileExistsError:
            pass
        except OSError:
            return None
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return None


def collector(override: str = None, evidence_dir: str = None) -> dict:
    """Who collects. An analyst-supplied name ($CTI_COLLECTOR / --collector) is recorded as given.
    Otherwise the raw OS login is NEVER written — manifests are shared evidence — but a stable
    per-case pseudonym is: sha256 of the case salt and the login. Outside a case store there is no
    salt, so the collector is null with the reason."""
    env = IDENTITY.get("collector_env") or "CTI_COLLECTOR"
    name = override or os.environ.get(env)
    if name:
        return {"collector": name, "collector_source": "analyst-supplied"}
    try:
        login = getpass.getuser()
    except Exception:                  # noqa: BLE001 — no user database in some containers
        login = None
    if not login:
        return {"collector": None, "collector_source": f"unknown — set {env}"}
    salt = _case_salt(evidence_dir)
    if not salt:
        return {"collector": None,
                "collector_source": f"not recorded — no case store to salt a pseudonym; set {env}"}
    pid = hashlib.sha256(f"{salt}:{login}".encode("utf-8")).hexdigest()[:16]
    return {"collector": f"collector-{pid}",
            "collector_source": f"pseudonym — sha256(case salt, OS login); set {env} to name the "
                                f"analyst"}


def _endpoint(proxy: str):
    """`host:port` of a proxy URL with any credentials dropped — a manifest is shared evidence and
    must never carry the pool's password. An IPv6 host stays bracketed; a bad port is dropped."""
    if not proxy:
        return None
    try:
        u = urlsplit(proxy if "://" in proxy else "http://" + proxy)
        host = u.hostname
    except ValueError:
        return None
    if not host:
        return None
    if ":" in host:
        host = f"[{host}]"
    try:
        port = u.port
    except ValueError:
        port = None
    return f"{host}:{port}" if port else host


def egress(proxy_used: str = None, override: str = None) -> dict:
    """The egress the target saw. Never looked up over the network at collection time: a confirmed
    IP comes from the analyst (`proxy.py test` → `--egress-ip` / CTI_EGRESS_IP); otherwise a public
    IP-literal proxy endpoint is recorded as the assumed exit; otherwise null, with the reason.
    Never raises: an unparseable proxy string is recorded as such."""
    try:
        return _egress(proxy_used, override)
    except Exception:                  # noqa: BLE001 — a manifest field must never abort a capture
        return {"egress_ip": None, "egress_proxy": None,
                "egress_note": "proxy string could not be parsed; egress not recorded — confirm "
                               "with proxy.py test and pass --egress-ip"}


def _egress(proxy_used, override):
    ep = _endpoint(proxy_used)
    ip = override or os.environ.get(IDENTITY.get("egress_env") or "CTI_EGRESS_IP")
    if ip:
        return {"egress_ip": ip, "egress_proxy": ep,
                "egress_note": "analyst-confirmed egress (proxy.py test)"}
    if ep:
        host = urlsplit("http://" + ep).hostname
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            addr = None
        if addr is not None and addr.is_global:
            return {"egress_ip": host, "egress_proxy": ep,
                    "egress_note": "proxy endpoint, assumed to be the exit — a chained or rotating "
                                   "proxy can exit elsewhere; confirm with proxy.py test"}
        return {"egress_ip": None, "egress_proxy": ep,
                "egress_note": f"proxy {ep} used; its exit IP was not resolved (no network call at "
                               f"collection) — confirm with proxy.py test and pass --egress-ip"}
    return {"egress_ip": None, "egress_proxy": None,
            "egress_note": "direct connection; the collecting host's public IP was not looked up "
                           "(no network call at collection) — pass --egress-ip once checked"}


def persona(override: str = None) -> dict:
    p = override or os.environ.get(IDENTITY.get("persona_env") or "CTI_PERSONA")
    return {"persona": p or None}


def clock_sync(commands: list = None, runner=subprocess.run) -> dict:
    """The local clock-sync state at collection start: `synced`, `not_synced` or `unknown`.
    Reads only the host's own time daemon; never a network time service."""
    for spec in (CLOCK_COMMANDS if commands is None else commands):
        argv = list(spec.get("argv") or [])
        if not argv or not shutil.which(argv[0]):
            continue
        try:
            r = runner(argv, capture_output=True, text=True,
                       timeout=float(spec.get("timeout_seconds") or 3))
        except Exception:              # noqa: BLE001 — timeout / no D-Bus: unknown, not a guess
            continue
        val = (r.stdout or "").strip()
        state = ("synced" if val in (spec.get("synced") or []) else
                 "not_synced" if val in (spec.get("not_synced") or []) else None)
        if state and r.returncode == 0:
            return {"state": state, "source": spec.get("source") or argv[0], "checked_at": utc_iso()}
    return {"state": "unknown", "source": "no local clock-sync status readable on this host",
            "checked_at": utc_iso()}


def collection_context(proxy_used: str = None, collector_name: str = None, persona_name: str = None,
                       egress_ip: str = None, evidence_dir: str = None) -> dict:
    """The ¶155(g) collection-data block merged into a manifest. `evidence_dir` is the case store
    whose salt pseudonymises an unnamed collector."""
    ctx = {}
    ctx.update(collector(collector_name, evidence_dir))
    ctx.update(persona(persona_name))
    ctx.update(egress(proxy_used, egress_ip))
    ctx["clock_sync"] = clock_sync()
    return ctx


# --------------------------------------------------------------------------- the custody log
def evidence_root(path: str):
    """The case evidence directory holding `path` (nearest ancestor named `evidence`), or None when
    the item is not in a case store — an ad-hoc `--outdir` capture has no custody log."""
    name = LAYOUT.get("evidence_dir") or "evidence"
    p = os.path.abspath(path)
    while True:
        if os.path.basename(p) == name and os.path.isdir(p):
            return p
        parent = os.path.dirname(p)
        if parent == p:
            return None
        p = parent


def case_evidence_dir(case: str, root: str = ".") -> str:
    return os.path.join(root, "cases", case, LAYOUT.get("evidence_dir") or "evidence")


def log_path(evidence_dir: str) -> str:
    return os.path.join(evidence_dir, LAYOUT.get("log_filename") or "custody.jsonl")


def item_ref(evidence_dir: str, path: str) -> str:
    """The item as a path relative to the CASE directory, so the log survives moving the case."""
    case_dir = os.path.dirname(os.path.abspath(evidence_dir))
    rel = os.path.relpath(os.path.abspath(path), case_dir)
    return rel.replace(os.sep, "/")


def contained_ref(case_dir: str, item: str):
    """`item` (relative to the case directory) normalised to a case-relative ref, or None when it is
    absolute, empty, or its realpath leaves the case directory — a log line must never point fixity
    (which verifies, seals and logs) at another case or the host."""
    if not item or not isinstance(item, str) or "\x00" in item or os.path.isabs(item):
        return None
    try:
        base = os.path.realpath(case_dir)
        full = os.path.realpath(os.path.join(base, item))
    except (OSError, ValueError):
        return None
    if full == base or not full.startswith(base + os.sep):
        return None
    return os.path.relpath(full, base).replace(os.sep, "/")


def _line_hash(raw: bytes) -> str:
    return hashlib.sha256(raw.rstrip(b"\r\n")).hexdigest()


def _head(sha: str, n: int) -> dict:
    return {"sha256": sha, "entries": n, "anchor": f"{sha}:{n}"}


def parse_head(head):
    """(sha256, entries) from a head dict or its `<sha256>:<entries>` anchor string; None if unusable."""
    if isinstance(head, dict):
        sha, n = head.get("sha256"), head.get("entries")
        if isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha) and isinstance(n, int) \
                and not isinstance(n, bool) and n >= 0:
            return sha, n
        return None
    m = _HEAD_RE.match(str(head or "").strip())
    return (m.group(1), int(m.group(2))) if m else None


def append(evidence_dir: str, action: str, item: str, digest: str = None, note: str = None,
           actor: str = None) -> dict:
    """Append ONE custody line and return it with the new `head` (not written into the line).

    The file is only ever opened for append; the previous line's hash is read under an exclusive
    lock so concurrent writers still produce one linear chain. A torn last line (a crash or a full
    disk mid-write) is terminated with a newline first, so it stays one recognisable line instead
    of fusing with this one. The write is fsync'd. `prev` is the first key, so even a torn line
    keeps its link to the line before."""
    if action not in ACTIONS:
        raise ValueError(f"unknown custody action {action!r} — one of {', '.join(ACTIONS)}")
    os.makedirs(evidence_dir, exist_ok=True)
    path = log_path(evidence_dir)
    entry = {"prev": None, "utc": utc_iso(), "action": action,
             "actor": actor or collector(None, evidence_dir).get("collector"),
             "item": item, "sha256": digest, "note": note}
    with open(path, "ab+") as fh:
        if fcntl:
            fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            fh.seek(0)
            prev, n, last = GENESIS, 0, b""
            for raw in fh:
                if raw.strip():
                    prev, n = _line_hash(raw), n + 1
                last = raw
            entry["prev"] = prev
            fh.seek(0, os.SEEK_END)
            if last and not last.endswith(b"\n"):
                fh.write(b"\n")
            line = json.dumps(entry, ensure_ascii=False, sort_keys=False).encode("utf-8")
            fh.write(line + b"\n")
            fh.flush()
            os.fsync(fh.fileno())
        finally:
            if fcntl:
                fcntl.flock(fh, fcntl.LOCK_UN)
    return dict(entry, head=_head(_line_hash(line), n + 1))


def read_log(evidence_dir: str) -> list:
    path = log_path(evidence_dir)
    if not os.path.isfile(path):
        return []
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.strip():
                try:
                    obj = json.loads(line)
                except ValueError:
                    obj = None
                out.append(obj if isinstance(obj, dict) else {"_unparseable": line.rstrip("\n")})
    return out


def first_capture_digest(evidence_dir: str, item: str):
    """The digest of the FIRST `capture` line logged for `item`, or None. This is the value an item
    is held to: a manifest sits beside the evidence and can be rewritten with it; the log line
    written at collection is chained and anchored."""
    for e in read_log(evidence_dir):
        if e.get("action") == "capture" and e.get("item") == item and e.get("sha256"):
            return e["sha256"]
    return None


def check_log(evidence_dir: str, expected_head=None) -> dict:
    """Walk the hash chain and return the current `head`.

    An edited, removed or reordered line breaks the chain at the line that follows it. Cutting
    lines off the END, or rewriting the last line, leaves a valid shorter chain — only a head
    recorded earlier (`expected_head`: a head dict or its `<sha256>:<entries>` anchor) shows it:
    `head_check` is `truncated` when the log has fewer entries than that head, `mismatch` when the
    anchored line no longer hashes to it. An unparseable line is reported in `torn` and fails the
    check; the chain is still followed through it via any `prev` it carries, without claiming to
    distinguish an interrupted write from an edit. A last line with no newline is `torn_tail`."""
    path = log_path(evidence_dir)
    exp = None
    if expected_head is not None:
        exp = parse_head(expected_head)
        if exp is None:
            return {"ok": False, "path": path, "entries": None, "broken_at": None, "head": None,
                    "torn": [], "torn_tail": False, "head_check": "unparseable",
                    "expected_head": expected_head,
                    "note": "expected head is not '<sha256>:<entries>' — nothing was compared"}
    prev, n = GENESIS, 0
    torn, unlinked, tail_torn, broken = [], [], False, None
    anchor = GENESIS if exp and exp[1] == 0 else None
    if os.path.isfile(path):
        with open(path, "rb") as fh:
            for raw in fh:
                if not raw.strip():
                    continue
                n += 1
                tail_torn = not raw.endswith(b"\n")
                try:
                    obj = json.loads(raw)
                except ValueError:
                    obj = None
                if isinstance(obj, dict):
                    got = obj.get("prev")
                else:
                    torn.append(n)
                    m = _PREV_RE.search(raw)
                    got = m.group(1).decode() if m else prev
                    if not m:
                        unlinked.append(n)
                if got != prev:
                    broken = n
                    break
                prev = _line_hash(raw)
                if exp and n == exp[1]:
                    anchor = prev
    head = _head(prev, n)
    out = {"ok": True, "path": path, "entries": n, "broken_at": broken, "head": head,
           "torn": torn, "torn_tail": tail_torn, "head_check": None,
           "expected_head": _head(*exp) if exp else None}
    if broken:
        out.update(ok=False, head=None,
                   note=f"custody chain broken at line {broken}: the log was edited or reordered "
                        f"after it was written")
        return out
    notes = []
    if not os.path.isfile(path):
        notes.append("no custody log yet")
    if exp:
        if n < exp[1]:
            out["head_check"] = "truncated"
            notes.append(f"TRUNCATED — the log has {n} entries but the recorded head names "
                         f"{exp[1]}: lines were removed from the end")
        elif anchor != exp[0]:
            out["head_check"] = "mismatch"
            notes.append(f"HEAD MISMATCH — line {exp[1]} no longer hashes to the recorded head: the "
                         f"log was rewritten up to that line")
        else:
            out["head_check"] = "match"
    if tail_torn:
        notes.append(f"the last line ({n}) is TORN — no trailing newline; the next append "
                     f"terminates it without discarding any bytes")
    if torn:
        notes.append(f"torn or malformed line(s) {', '.join(map(str, torn))}; these events are "
                     f"incomplete — an interrupted write and an edit cannot be distinguished")
    if unlinked:
        notes.append(f"torn line(s) {', '.join(map(str, unlinked))} lost their `prev`: the chain "
                     f"cannot be proved across them")
    out["ok"] = not tail_torn and not torn and not unlinked and out["head_check"] in (None, "match")
    out["note"] = "; ".join(notes) if notes else "chain intact"
    return out


# --------------------------------------------------------------------------- originals and copies
class SealError(Exception):
    """The identities verified but the permission change itself failed (read-only mount, EPERM,
    NotImplementedError). The content is intact; only the seal is missing — never tampering."""


def seal(path: str, handles=None) -> None:
    """Seal only pinned, verified inodes, never a pathname reopened after hashing.
    Each handle is (path, fd, fstat-at-hash); all identities are checked before any chmod."""
    if handles is None:
        with ExitStack() as stack:
            paths = []
            if os.path.isdir(path):
                for d, dirs, files in os.walk(path, followlinks=False):
                    paths.append((d, True))
                    paths.extend((os.path.join(d, f), False) for f in files)
                    if any(os.path.islink(os.path.join(d, n)) for n in dirs):
                        raise ValueError("symlink directory in evidence")
            else:
                paths.append((path, False))
            held = []
            for p, directory in paths:
                fd = stack.enter_context(pinned(p, directory))
                held.append((p, fd, os.fstat(fd)))
            return seal(path, held)
    for p, fd, hashed in handles:
        now, named = os.fstat(fd), os.lstat(p)
        if stat.S_ISLNK(named.st_mode) or inode_state(now) != inode_state(hashed) or (
                now.st_dev, now.st_ino) != (named.st_dev, named.st_ino):
            raise ValueError(f"evidence changed after hashing: {p}")
    done = 0
    for p, fd, hashed in reversed(handles):
        mode = _DIR_RO if stat.S_ISDIR(hashed.st_mode) else _FILE_RO
        if not hasattr(os, "fchmod"):  # Windows: refuse sealing rather than chmod a raced pathname.
            raise OSError("descriptor sealing unavailable on this platform")
        try:
            os.fchmod(fd, mode)
        except Exception as exc:  # noqa: BLE001 — any failure of the chmod itself is a seal failure
            raise SealError(f"{type(exc).__name__}: {exc} ({p}; {done} of {len(handles)} "
                            f"descriptor(s) already read-only)") from exc
        done += 1


def is_sealed(path: str) -> bool:
    w = 0o222
    if os.path.isfile(path):
        return not (os.stat(path).st_mode & w)
    for d, dirs, files in os.walk(path):
        if os.stat(d).st_mode & w:
            return False
        if any(os.stat(os.path.join(d, f)).st_mode & w for f in files):
            return False
    return True


def _tree(path: str) -> dict:
    out = {}
    for d, dirs, files in os.walk(path):
        for f in files:
            p = os.path.join(d, f)
            out[os.path.relpath(p, path).replace(os.sep, "/")] = file_sha256(p)
    return out


def _free(dst: str) -> str:
    if not os.path.exists(dst):
        return dst
    stem, ext = os.path.splitext(dst) if os.path.isfile(dst) else (dst, "")
    n = 2
    while os.path.exists(f"{stem}-copy{n}{ext}"):
        n += 1
    return f"{stem}-copy{n}{ext}"


def working_copy(src: str, actor: str = None, note: str = None) -> dict:
    """Copy an original (capture directory or screenshot PNG) into `evidence/work/<same path>`,
    writable, checked byte-for-byte against the original, and logged as a `copy` custody event.
    The original is only read."""
    ev = evidence_root(src)
    if not ev:
        return {"ok": False, "error": f"{src} is not inside a case evidence store — no work path"}
    if not os.path.exists(src):
        return {"ok": False, "error": f"no such item: {src}"}
    rel = os.path.relpath(os.path.abspath(src), ev)
    dst = _free(os.path.join(ev, LAYOUT.get("work_dir") or "work", rel))
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if os.path.isdir(src):
        # copyfile, not copy2: the copy must NOT inherit the original's read-only bits.
        shutil.copytree(src, dst, copy_function=shutil.copyfile)
        for d, dirs, files in os.walk(dst):
            os.chmod(d, _DIR_RW)
            for f in files:
                os.chmod(os.path.join(d, f), _FILE_RW)
        a, b = _tree(src), _tree(dst)
        digest = None
        man = os.path.join(src, "manifest.json")
        if os.path.isfile(man):
            try:
                with open(man, encoding="utf-8") as fh:
                    digest = json.load(fh).get("capture_sha256")
            except Exception:          # noqa: BLE001 — a damaged manifest still copies; say so
                digest = None
    else:
        shutil.copyfile(src, dst)
        os.chmod(dst, _FILE_RW)
        a = {os.path.basename(src): file_sha256(src)}
        b = {os.path.basename(src): file_sha256(dst)}
        digest = a[os.path.basename(src)]
    identical = a == b
    text = (f"working copy -> {item_ref(ev, dst)}; {len(b)} file(s) "
            + ("byte-identical to the original" if identical else "DIFFER from the original"))
    entry = append(ev, "copy", item_ref(ev, src), digest, (note + "; " if note else "") + text, actor)
    return {"ok": identical, "original": src, "copy": dst, "sha256": digest, "files": len(b),
            "custody": entry}


# --------------------------------------------------------------------------- fixity sampling
def sample(items: list, n: int = None, seed: int = None):
    """(seed_used, chosen): a reproducible random draw of `n` items. With no seed one is drawn from
    the OS and RETURNED, so the run can be replayed exactly."""
    n = int(FIXITY.get("default_sample") or 5) if n is None else int(n)
    if seed is None:
        seed = random.SystemRandom().randrange(2 ** 32)
    pool = sorted(items)
    return seed, random.Random(seed).sample(pool, min(max(n, 0), len(pool)))


__all__ = ["collection_context", "clock_sync", "egress", "collector", "persona", "evidence_root",
           "case_evidence_dir", "log_path", "item_ref", "append", "read_log", "check_log", "seal",
           "SealError",
           "is_sealed", "working_copy", "sample", "file_sha256", "ACTIONS", "FIXITY", "LAYOUT",
           "CLOCK_COMMANDS", "MANUAL_ACTIONS", "contained_ref", "first_capture_digest", "parse_head"]
