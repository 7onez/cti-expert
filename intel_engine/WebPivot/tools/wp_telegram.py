#!/usr/bin/env python3
"""wp_telegram — phone number / username / link → Telegram account LEAD (MTProto via Telethon).

Five subcommands, all run from the ANALYST's research account (except `age` on a numeric id):

  login     Interactive, in the analyst's own terminal. Default: Telethon's login flow prompts for
            the research account's phone, the login code and any 2FA password. `--qr`: scan a
            tg://login QR with the research account's phone (terminal QR / temp PNG; 2FA via
            getpass). `--tdata DIR --own-account`: import the analyst's OWN Telegram Desktop install
            as a NEW authorisation (opentele2). The tool never accepts a code, password, passcode,
            cookie or session string as an argument (SKILL.md rule).
  status    Is Telethon/opentele2 installed, which backend/profile/device the session is bound to,
            is it authorised. `--sessions` adds the account's active sessions and opentele2's
            consistency checks (read-only; nothing is terminated). Prints no secret.
  phone     E.164 number(s) → account, via contacts.ImportContacts with a random client_id, then
            ALWAYS contacts.DeleteContacts in `finally` (pre-existing contacts are left alone).
            OUTBOUND + attributable: without --confirm-import it returns a BRIEFING and sends nothing.
            FloodWait stops the run and returns the partial result.
  resolve   @username | t.me link | t.me/+invite | -100<id> → public entity metadata (users,
            channels, supergroups, invite previews) without importing anything. OUTBOUND from the
            research account: without --confirm it returns a BRIEFING and sends nothing.
  age       @username | t.me link | numeric user id → user id + ESTIMATED account creation date.
            A numeric id is dated offline (no Telegram call, no session, no confirm); a
            @username/link is resolved first — briefing only until --confirm. Channels/groups
            report Telegram's own `date` instead. Every user/bot row from `resolve` and `phone`
            also carries `created_estimate`.

Attribution rail (SKILL.md RULE 5): every row is `rung: "lead"` with a `caveat`. A phone→account
match proves the number is registered to that Telegram account — not who the person is; names,
usernames, bios and photos are self-set. Nothing here writes a KB edge or an operator link.

Optional dependencies, imported lazily: Telethon; opentele2 (a Telethon subclass presenting an
official Telegram app api_id + a deterministic realistic device — used when installed and either
no TELEGRAM_API_ID/HASH is set or `login --profile` is given); python-socks with a proxy; qrcode
(+ Pillow) for the QR. Missing → `{"skipped": ..., "setup": [...]}`. Stdlib-only at module level.
Never raises from the public functions — opentele2's exceptions derive from BaseException, so every
boundary catches `_errs()`; failures come back as `{"error": ...}` / per-row `error`.

Backend binding: the api_id + device are fixed ONCE at login and recorded in the sidecar (backend,
profile, unique_id, device fields); every later connection reuses exactly that — an authorisation
that changes api_id/device mid-life is what gets research accounts flagged.

Session: $TELEGRAM_SESSION, else `settings.session_default` in references/telegram.json (a per-user
config dir outside the repo). The session is a credential: a path inside the repo that git does
not ignore is refused. A sidecar `<session>.meta.json` (account id/username/first name only — no
phone) lets the offline briefing name the account without contacting Telegram.

Egress: Telethon opens raw MTProto sockets, so the process-global urllib proxy does not cover it.
When the repo's proxy pool is active its URL is handed to Telethon; if python-socks is missing the
tool skips rather than leak the host's own address.

CLI:
  python3 wp_telegram.py login [--qr] [--profile desktop|android|ios]
  python3 wp_telegram.py login --tdata DIR --own-account [--passcode-prompt] [--profile P]
  python3 wp_telegram.py status [--sessions]
  python3 wp_telegram.py phone +447700900000                 # briefing only, nothing sent
  python3 wp_telegram.py phone +447700900000 --confirm-import [--save-photo DIR] [--case CASE-0001]
  python3 wp_telegram.py resolve @example_channel            # briefing only, nothing sent
  python3 wp_telegram.py resolve @example_channel --confirm
  python3 wp_telegram.py resolve https://t.me/+AbCdEfGhIjKl --confirm
  python3 wp_telegram.py age 7000000001                       # offline, no confirm needed
  python3 wp_telegram.py age @example_user t.me/example_user --confirm [--case CASE-0001]
"""
import argparse
import asyncio
import bisect
import datetime
import getpass
import hashlib
import json
import os
import random
import re
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.dirname(os.path.dirname(HERE))
REPO = os.path.dirname(ENGINE)
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from wp_common import _secret  # noqa: E402 — loads the gitignored .env + installs the egress proxy
from wp_refs import ref_path, load_ref  # noqa: E402 — reference DATA lives in references/*.json

TOOL = "telegram_lookup"

_FALLBACK = {
    "settings": {"session_default": "~/.config/cti-expert/sessions/telegram.session",
                 "max_phones_per_run": 5, "import_delay_seconds": 5, "flood_sleep_threshold": 0,
                 "connect_timeout_seconds": 20, "photo_max_bytes": 5242880,
                 "default_profile": "desktop", "desktop_system": "windows",
                 "qr_wait_seconds": 120, "qr_max_recreate": 10, "qr_png_prefix": "cti-tgqr-",
                 "max_resolve_per_run": 5, "age_neighbours": 12, "age_error_percentile": 0.8,
                 "age_tail_fit_days": 365, "age_confidence_days": {"high": 30, "medium": 90}},
    "profiles": {"desktop": "TelegramDesktop", "android": "TelegramAndroid", "ios": "TelegramIOS"},
    "stealer_log_markers": ["Passwords.txt", "All Passwords.txt", "Autofills", "Cookies", "Wallets",
                            "System.txt", "UserInformation.txt", "Information.txt", "Browsers"],
    "status_buckets": {"UserStatusOnline": "online", "UserStatusOffline": "offline",
                       "UserStatusRecently": "recently", "UserStatusEmpty": "hidden_or_long_ago"},
    "link_patterns": {
        "invite": r"^(?:t\.me|telegram\.me|telegram\.dog)/(?:\+|joinchat/)([A-Za-z0-9_-]{8,})",
        "private_channel": r"^(?:t\.me|telegram\.me|telegram\.dog)/c/(\d+)",
        "username": r"^(?:(?:t\.me|telegram\.me|telegram\.dog)/(?:s/)?|@)?([A-Za-z][A-Za-z0-9_]{3,31})(?:[/?#].*)?$",
        "peer_id": r"^(-100\d+|\d+)$"},
    "caveats": {"phone": "LEAD only: a phone match proves registration of the number to this "
                         "account, not who the person is.",
                "not_found": "No account returned; privacy settings can hide a registered number.",
                "resolve": "LEAD only: public entity metadata.",
                "names": "Names, usernames, bios and photos are self-set.",
                "age": "ESTIMATE from public user-id → creation-date anchors; Telegram never "
                       "publishes a registration date. Read the range, not the day."},
    "briefing": ["Sends contacts.ImportContacts for {n} number(s) from {account}; re-run with "
                 "--confirm-import to send."],
    "resolve_briefing": ["Sends one username/link resolve per target ({n}: {targets}) from the "
                         "research account {account}; re-run with --confirm to send."],
    "setup": ["pip install telethon (or opentele2); set TELEGRAM_API_ID / TELEGRAM_API_HASH unless "
              "using opentele2; run wp_telegram.py login [--qr] in your terminal."],
    # conservative minimum: a coarse curve whose error band is wide — the reference file carries
    # the full anchor set (references/telegram.json → id_date_anchors)
    "id_date_anchors": [[0, "2013-08-14"], [101260938, "2015-03-06"], [352940995, "2017-02-24"],
                        [1974255900, "2021-10-12"], [5070164216, "2022-01-19"],
                        [6271031786, "2023-02-12"], [7224009547, "2024-08-02"],
                        [8559682245, "2025-11-11"]],
}
REF = load_ref(ref_path(__file__, "telegram.json"), _FALLBACK)
SET = REF["settings"]
CAV = REF["caveats"]
_E164 = re.compile(r"^\+[1-9]\d{6,14}$")


# --------------------------------------------------------------------------- helpers
def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso(d):
    if isinstance(d, datetime.datetime):
        if d.tzinfo is None:
            d = d.replace(tzinfo=datetime.timezone.utc)
        return d.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return None


def _caveat(kind):
    return f"{CAV.get(kind, '')} {CAV.get('names', '')}".strip()


def _skip(reason, **extra):
    out = {"tool": TOOL, "skipped": reason, "setup": list(REF["setup"])}
    out.update(extra)
    return out


def session_path():
    p = os.environ.get("TELEGRAM_SESSION") or SET.get("session_default") or _FALLBACK["settings"]["session_default"]
    p = os.path.abspath(os.path.expanduser(p))
    return p if p.endswith(".session") else p + ".session"


def _meta_path(sess):
    return sess[:-len(".session")] + ".meta.json"


def _unsafe_repo_path(path):
    """A path inside the repo that git does NOT ignore → reason string, else None. A session is a
    credential and a profile photo is case data; neither may land somewhere committable."""
    rp, repo = os.path.realpath(path), os.path.realpath(REPO)
    if not (rp == repo or rp.startswith(repo + os.sep)):
        return None
    try:
        r = subprocess.run(["git", "-C", repo, "check-ignore", "-q", rp],
                           capture_output=True, timeout=10)
        if r.returncode == 0:
            return None
    except Exception:  # noqa: BLE001 — no git: be conservative
        pass
    return (f"{path} is inside the repo and not gitignored — refusing to write a credential/case "
            f"artifact where it could be committed. Use a path outside the repo or a gitignored one.")


def _creds():
    api_id, api_hash = _secret("TELEGRAM_API_ID"), _secret("TELEGRAM_API_HASH")
    if not api_id or not api_hash:
        return None
    try:
        return int(api_id), api_hash
    except ValueError:
        return None


def _proxy_for_telethon():
    """(proxy_dict_or_None, problem_or_None) from the process egress the repo installed."""
    url = (os.environ.get("ALL_PROXY") or os.environ.get("all_proxy") or os.environ.get("HTTPS_PROXY")
           or os.environ.get("https_proxy") or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy"))
    if not url:
        return None, None
    from urllib.parse import urlsplit
    u = urlsplit(url if "://" in url else "http://" + url)
    scheme = (u.scheme or "http").lower()
    ptype = {"socks5": "socks5", "socks5h": "socks5", "socks4": "socks4",
             "http": "http", "https": "http"}.get(scheme)
    if not ptype or not u.hostname or not u.port:
        return None, f"unsupported proxy URL scheme for MTProto: {scheme}"
    try:
        import python_socks  # noqa: F401 — Telethon needs it for any proxy
    except ImportError:
        return None, ("a proxy is configured but python-socks is not installed — refusing to connect "
                      "to Telegram directly from this host (pip install python-socks, or disable the "
                      "proxy deliberately with CTI_PROXY_ENABLED=0)")
    d = {"proxy_type": ptype, "addr": u.hostname, "port": u.port, "rdns": True}
    if u.username:
        d["username"], d["password"] = u.username, u.password or ""
    return d, None


def _import_telethon():
    """Return a namespace {TelegramClient, functions, types, errors, utils} or None."""
    try:
        import telethon
        from telethon import TelegramClient, functions, types, errors, utils
    except ImportError:
        return None
    return {"TelegramClient": TelegramClient, "functions": functions, "types": types,
            "errors": errors, "utils": utils, "version": getattr(telethon, "__version__", "?")}


def _import_opentele2():
    """opentele2 (a Telethon subclass that presents an official app's api_id + a realistic device)
    or None. Its exceptions derive from BaseException, NOT Exception — see _errs()."""
    try:
        import opentele2
        from opentele2.tl import TelegramClient
        from opentele2.api import API, UseCurrentSession, CreateNewSession
        from opentele2.td import TDesktop
        from opentele2.exception import OpenTeleException
    except ImportError:
        return None
    except BaseException:  # noqa: BLE001 — a broken install must not crash the tool
        return None
    return {"TelegramClient": TelegramClient, "API": API, "UseCurrentSession": UseCurrentSession,
            "CreateNewSession": CreateNewSession, "TDesktop": TDesktop,
            "OpenTeleException": OpenTeleException,
            "version": getattr(opentele2, "__version__", None) or _dist_version("opentele2")}


def _dist_version(name):
    try:
        from importlib.metadata import version
        return version(name)
    except Exception:  # noqa: BLE001
        return "?"


def _errs():
    """Exception classes every tri-state boundary catches: Exception plus opentele2's
    OpenTeleException (a BaseException subclass that `except Exception` would let through)."""
    try:
        from opentele2.exception import OpenTeleException
        return (Exception, OpenTeleException)
    except BaseException:  # noqa: BLE001
        return (Exception,)


def _profiles():
    return dict(REF.get("profiles") or _FALLBACK["profiles"])


def select_backend(profile, has_telethon, has_opentele2, has_creds, meta=None):
    """(backend, profile, problem). The session sidecar wins: an authorisation must keep the SAME
    api_id + device it was created with — switching mid-life is what gets research accounts flagged.
    Fresh login: opentele2 when installed and (no own API id, or a --profile was asked for); else
    plain Telethon with TELEGRAM_API_ID / TELEGRAM_API_HASH."""
    default = SET.get("default_profile", "desktop")
    if profile and profile not in _profiles():
        return None, None, f"unknown --profile {profile!r} (choose from {', '.join(_profiles())})"
    if profile and not has_opentele2:
        return None, None, "--profile needs opentele2 (pip install opentele2)"
    b = (meta or {}).get("backend") if meta else None
    if meta is not None and not b:
        b = "telethon"                         # sidecar from before backends were recorded
    if b == "opentele2":
        if not has_opentele2:
            return None, None, ("this session was created with opentele2 — install opentele2; "
                                "connecting with another api_id/device would flag the account")
        if profile and profile != meta.get("profile"):
            return None, None, (f"this session was created with profile {meta.get('profile')!r}; "
                                f"--profile {profile!r} would change the device. Use a new "
                                f"TELEGRAM_SESSION path for a different profile")
        return "opentele2", meta.get("profile") or default, None
    if b == "telethon":
        if profile:
            return None, None, ("this session was created with your own API id (plain Telethon); "
                                "--profile would change the api_id/device. Use a new "
                                "TELEGRAM_SESSION path for a profile login")
        if not has_telethon:
            return None, None, "telethon not installed (optional dependency)"
        if not has_creds:
            return None, None, ("this session was created with TELEGRAM_API_ID / TELEGRAM_API_HASH "
                                "— set them again (the session is bound to that api_id)")
        return "telethon", None, None
    if has_opentele2 and (not has_creds or profile):
        return "opentele2", profile or default, None
    if not has_telethon:
        return None, None, "telethon not installed (optional dependency)"
    if not has_creds:
        return None, None, ("TELEGRAM_API_ID / TELEGRAM_API_HASH not set (or API_ID not numeric), "
                            "and opentele2 is not installed")
    return "telethon", None, None


def _backend(profile=None, need_session=True, force_opentele2=False):
    """The connection context `be` (dict) or a skip dict."""
    tl, ot = _import_telethon(), _import_opentele2()
    creds = _creds()
    sess = session_path()
    bad = _unsafe_repo_path(sess)
    if bad:
        return _skip(bad)
    meta = _read_meta(sess) if os.path.isfile(sess) else None
    if force_opentele2 and not ot:
        return _skip("this login mode needs opentele2 (pip install opentele2)")
    backend, prof, problem = select_backend(profile, tl is not None, ot is not None,
                                            creds is not None, meta)
    if force_opentele2 and backend == "telethon" and meta is None:
        backend, prof, problem = "opentele2", profile or SET.get("default_profile", "desktop"), None
    if problem:
        return _skip(problem)
    if force_opentele2 and backend != "opentele2":
        return _skip("this session was created with plain Telethon; use a new TELEGRAM_SESSION "
                     "path for a tdata import")
    if need_session and not os.path.isfile(sess):
        return _skip(f"no Telegram session at {sess} — run the interactive `login` first",
                     session=sess)
    proxy, pproblem = _proxy_for_telethon()
    if pproblem:
        return _skip(pproblem)
    return {"backend": backend, "profile": prof, "tl": tl, "ot": ot, "creds": creds,
            "sess": sess, "proxy": proxy, "meta": meta or {}, "api": None}


_API_FIELDS = ("api_id", "device_model", "system_version", "app_version", "lang_code",
               "system_lang_code", "lang_pack")


def _api_class(ot, profile):
    return getattr(ot["API"], _profiles().get(profile, "TelegramDesktop"))


def generate_api(ot, profile, unique_id):
    """A deterministic official-app api + device for (profile, unique_id). No network."""
    cls = _api_class(ot, profile)
    if profile == "desktop":
        return cls.Generate(system=SET.get("desktop_system", "windows"), unique_id=unique_id)
    return cls.Generate(unique_id=unique_id)


def api_snapshot(api):
    """The device fields stored in the sidecar (the api_hash is the public official one and is
    re-derived from the profile class, so it is not stored)."""
    return {k: getattr(api, k, None) for k in _API_FIELDS}


def _api_from_meta(ot, meta):
    snap = (meta or {}).get("api")
    if snap:
        return _api_class(ot, meta.get("profile"))(**snap)
    if meta and meta.get("unique_id"):
        return generate_api(ot, meta.get("profile") or "desktop", meta["unique_id"])
    return None


def _client_kwargs(be):
    kw = {"timeout": int(SET.get("connect_timeout_seconds", 20)),
          "flood_sleep_threshold": int(SET.get("flood_sleep_threshold", 0))}
    if be.get("proxy"):
        kw["proxy"] = be["proxy"]
    return kw


def _client(be):
    kw = _client_kwargs(be)
    if be["backend"] == "opentele2":
        api = be.get("api") or _api_from_meta(be["ot"], be.get("meta"))
        if api is None:
            raise RuntimeError("opentele2 session has no recorded api/device in its sidecar — "
                               "log in again into a new TELEGRAM_SESSION path")
        return be["ot"]["TelegramClient"](be["sess"], api=api, **kw)
    return be["tl"]["TelegramClient"](be["sess"], be["creds"][0], be["creds"][1], **kw)


def _account_label(meta):
    if not meta or meta.get("id") is None:
        return "(account unknown — run status)"
    u = meta.get("username")
    return f"id {meta.get('id')}" + (f" @{u}" if u else "") + (f" ({meta.get('first_name')})" if meta.get("first_name") else "")


def _read_meta(sess):
    try:
        with open(_meta_path(sess), encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:  # noqa: BLE001
        return None


def _write_meta(sess, me, extra=None):
    """Merge the account identity (+ backend/profile/unique_id/api on login) into the sidecar.
    Never the phone number, never the api_hash, never session bytes."""
    meta = _read_meta(sess) or {}
    meta.update(extra or {})
    if me is not None:
        meta.update({"id": getattr(me, "id", None), "username": getattr(me, "username", None),
                     "first_name": getattr(me, "first_name", None),
                     "bot": bool(getattr(me, "bot", False))})
    meta["checked"] = _now()
    meta.setdefault("backend", "telethon")
    try:
        p = _meta_path(sess)
        os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(meta, fh)
        os.chmod(p, 0o600)
    except OSError:
        pass
    return meta


def _image_dims(b):
    """(width, height) of a JPEG/PNG/WebP byte string, else (None, None). Stdlib only."""
    try:
        if b[:8] == b"\x89PNG\r\n\x1a\n":
            return struct.unpack(">II", b[16:24])
        if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
            if b[12:16] == b"VP8X":
                return (int.from_bytes(b[24:27], "little") + 1, int.from_bytes(b[27:30], "little") + 1)
            if b[12:16] == b"VP8 ":
                w, h = struct.unpack("<HH", b[26:30])
                return w & 0x3FFF, h & 0x3FFF
        if b[:2] == b"\xff\xd8":
            i = 2
            while i + 9 < len(b):
                if b[i] != 0xFF:
                    i += 1
                    continue
                m = b[i + 1]
                if m in (0xD8, 0x01) or 0xD0 <= m <= 0xD7:
                    i += 2
                    continue
                seg = struct.unpack(">H", b[i + 2:i + 4])[0]
                if m in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                    h, w = struct.unpack(">HH", b[i + 5:i + 9])
                    return w, h
                i += 2 + seg
    except Exception:  # noqa: BLE001
        pass
    return None, None


def _status(user):
    st = getattr(user, "status", None)
    if st is None:
        return {"bucket": REF["status_buckets"].get("UserStatusEmpty", "hidden_or_long_ago")}
    name = type(st).__name__
    out = {"bucket": REF["status_buckets"].get(name, name)}
    if getattr(st, "was_online", None):
        out["was_online"] = _iso(st.was_online)
    if getattr(st, "expires", None):
        out["online_until"] = _iso(st.expires)
    return out


def _usernames(ent):
    names = []
    if getattr(ent, "username", None):
        names.append({"username": ent.username, "active": True, "collectible": False})
    for u in getattr(ent, "usernames", None) or []:
        n = getattr(u, "username", None)
        if n and not any(x["username"] == n for x in names):
            names.append({"username": n, "active": bool(getattr(u, "active", False)),
                          "collectible": not bool(getattr(u, "editable", False))})
    return names


def _restrictions(ent):
    return [{"platform": getattr(r, "platform", None), "reason": getattr(r, "reason", None),
             "text": getattr(r, "text", None)} for r in (getattr(ent, "restriction_reason", None) or [])]


def _user_row(user):
    return {"type": "bot" if getattr(user, "bot", False) else "user",
            "id": getattr(user, "id", None),
            "usernames": _usernames(user),
            "first_name": getattr(user, "first_name", None),
            "last_name": getattr(user, "last_name", None),
            "flags": {k: bool(getattr(user, k, False))
                      for k in ("bot", "verified", "premium", "scam", "fake", "restricted", "deleted")},
            "restriction_reason": _restrictions(user),
            "lang_code": getattr(user, "lang_code", None),
            "status": _status(user),
            "has_photo": getattr(user, "photo", None) is not None,
            "created_estimate": (estimate_creation(user.id) if getattr(user, "id", None) is not None
                                 else None)}


async def _photo(client, ent, save_dir):
    if getattr(ent, "photo", None) is None:
        return None
    try:
        b = await client.download_profile_photo(ent, file=bytes)
    except _errs() as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"}
    if not b:
        return None
    if len(b) > int(SET.get("photo_max_bytes", 5242880)):
        return {"error": "photo larger than photo_max_bytes; not processed"}
    w, h = _image_dims(b)
    out = {"sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b), "width": w, "height": h}
    if save_dir:
        try:
            os.makedirs(save_dir, exist_ok=True)
            p = os.path.join(save_dir, out["sha256"] + ".jpg")
            with open(p, "wb") as fh:
                fh.write(b)
            out["saved"] = p
        except OSError as e:
            out["save_error"] = str(e)
    return out


def _flood(tl, exc):
    errs = tl["errors"]
    fw = getattr(errs, "FloodWaitError", None)
    if fw is not None and isinstance(exc, fw):
        return {"error": "FloodWait", "seconds": getattr(exc, "seconds", None)}
    pf = getattr(errs, "PeerFloodError", None)
    if pf is not None and isinstance(exc, pf):
        return {"error": "PeerFlood", "seconds": None}
    return None


# --------------------------------------------------------------------------- creation estimate
# Telegram never publishes when an account was registered, but user ids come from one growing
# counter, so a curve through public (id, known creation date) anchors dates any user id. Offline,
# deterministic, no session: this is the only Telegram fact here that needs no research account.
_DAY = 86400.0
_CURVE = None


def _anchor_ts(d):
    return datetime.datetime.strptime(str(d)[:10], "%Y-%m-%d").replace(
        tzinfo=datetime.timezone.utc).timestamp()


def _day(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d")


def _isotonic(points):
    """Non-decreasing fit of time over id (pool adjacent violators); each pooled block becomes one
    knot at its mean (id, time). Ids since 2022 come from parallel ranges, so raw anchor-to-anchor
    interpolation zig-zags back in time; the pooled curve never does."""
    blocks = []
    for uid, t in points:
        blocks.append([uid, t, 1])
        while len(blocks) > 1 and blocks[-2][1] * blocks[-1][2] > blocks[-1][1] * blocks[-2][2]:
            sid, st, n = blocks.pop()
            blocks[-1][0] += sid
            blocks[-1][1] += st
            blocks[-1][2] += n
    return [(b[0] / b[2], b[1] / b[2]) for b in blocks]


def _tail_slope(knots, days):
    """Seconds per id over the last `days` of the fitted curve (extrapolation past the newest
    anchor); None when the curve has no usable tail."""
    if len(knots) < 2:
        return None
    x2, y2 = knots[-1]
    for x1, y1 in knots:
        if y2 - y1 <= days * _DAY and x2 > x1 and y2 > y1:
            return (y2 - y1) / (x2 - x1)
    x1, y1 = knots[-2]
    return (y2 - y1) / (x2 - x1) if x2 > x1 and y2 > y1 else None


def _fit_at(knots, xs, uid, slope):
    j = bisect.bisect_right(xs, uid)
    if j == 0:
        return knots[0][1]
    if j >= len(knots):
        return knots[-1][1] + (uid - knots[-1][0]) * (slope or 0.0)
    (x1, y1), (x2, y2) = knots[j - 1], knots[j]
    return y1 + (y2 - y1) * (uid - x1) / (x2 - x1)


def _build_curve(anchors, tail_days):
    pts = []
    for a in anchors or []:
        try:
            pts.append((int(a[0]), _anchor_ts(a[1])))
        except (TypeError, ValueError, IndexError):
            continue
    pts.sort()
    if len(pts) < 3:
        return None
    knots = _isotonic(pts)
    xs = [k[0] for k in knots]
    slope = _tail_slope(knots, tail_days)
    # leave-one-out error of every anchor: how far a KNOWN account would land had it not been in
    # the data — the honest per-range error (in-sample residuals understate it)
    loo = []
    for i, (uid, t) in enumerate(pts):
        k = _isotonic(pts[:i] + pts[i + 1:])
        loo.append(abs(_fit_at(k, [p[0] for p in k], uid, _tail_slope(k, tail_days)) - t) / _DAY)
    return {"points": pts, "knots": knots, "xs": xs, "slope": slope, "loo": loo,
            "max_id": pts[-1][0], "newest": max(t for _, t in pts), "oldest": min(t for _, t in pts)}


def _curve():
    global _CURVE
    if _CURVE is None:
        _CURVE = _build_curve(REF.get("id_date_anchors"), float(SET.get("age_tail_fit_days", 365))) or {}
    return _CURVE or None


def _age_text(created, now):
    a = datetime.datetime.fromtimestamp(created, datetime.timezone.utc)
    b = datetime.datetime.fromtimestamp(now, datetime.timezone.utc)
    months = max(0, (b.year - a.year) * 12 + b.month - a.month - (b.day < a.day))
    return f"{months // 12}y {months % 12}m"


def estimate_creation(user_id, now=None):
    """User/bot id → estimated creation date, error band and age. Never raises; a non-user id
    (≤ 0, i.e. a chat or -100… channel) returns {"error": …}."""
    try:
        uid = int(str(user_id).strip())
    except (TypeError, ValueError):
        return {"error": "not a numeric Telegram user id"}
    if uid <= 0:
        return {"error": "negative / -100… ids are groups or channels: they use a separate counter "
                         "and are dated by `resolve` (entity.date), not by this curve"}
    c = _curve()
    if not c:
        return {"error": "no usable id_date_anchors in references/telegram.json"}
    now = float(now if now is not None else time.time())
    t = min(_fit_at(c["knots"], c["xs"], uid, c["slope"]), now)
    k = max(3, int(SET.get("age_neighbours", 12)))
    near = sorted(range(len(c["points"])), key=lambda i: abs(c["points"][i][0] - uid))[:k]
    errs = sorted(c["loo"][i] for i in near)
    pct = min(1.0, max(0.0, float(SET.get("age_error_percentile", 0.8))))
    err = errs[round(pct * (len(errs) - 1))]
    extrapolated = uid > c["max_id"]
    lo, hi = max(t - err * _DAY, c["oldest"]), min(t + err * _DAY, now)
    if extrapolated:
        hi = now                      # past the newest anchor the curve only bounds from below
    conf_days = SET.get("age_confidence_days") or {}
    conf = ("low" if extrapolated else "high" if err <= float(conf_days.get("high", 30))
            else "medium" if err <= float(conf_days.get("medium", 90)) else "low")
    est = _day(t)
    return {"user_id": uid, "estimate": est, "month": est[:7],
            "range": {"from": _day(lo), "to": _day(hi)}, "error_days": int(round(err)),
            "age": _age_text(t, now), "age_days": int((now - t) // _DAY),
            "confidence": conf, "extrapolated": extrapolated,
            "method": (f"isotonic id→date curve over {len(c['points'])} public anchors (newest "
                       f"{_day(c['newest'])}); error = p{int(pct * 100)} leave-one-out error of "
                       f"the {len(near)} id-nearest anchors"),
            "caveat": CAV.get("age", "")}


# --------------------------------------------------------------------------- phone
def briefing(phones):
    sess = session_path()
    acct = _account_label(_read_meta(sess))
    fill = {"n": len(phones), "account": acct, "session": sess,
            "max": SET.get("max_phones_per_run"), "delay": SET.get("import_delay_seconds")}
    lines = []
    for t in REF["briefing"]:
        try:
            lines.append(t.format(**fill))
        except (KeyError, IndexError, ValueError):
            lines.append(t)
    return {"tool": TOOL, "mode": "phone", "confirm_required": True, "sent": False,
            "phones": phones, "research_account": acct, "session": sess,
            "session_present": os.path.isfile(sess), "briefing": lines}


async def _phone_async(make_client, tl, phones, save_dir=None, delay=None):
    F, T = tl["functions"], tl["types"]
    results, stopped, errors = [], None, []
    delay = float(SET.get("import_delay_seconds", 4) if delay is None else delay)
    client = make_client()      # built inside the running loop (Telethon binds the loop it sees)
    await client.connect()
    try:
        if not await client.is_user_authorized():
            return {"skipped": "session present but not authorised — run `login` again"}
        me = await client.get_me()
        meta = _write_meta(session_path(), me) if session_path() else None
        if getattr(me, "bot", False):
            return {"skipped": "the session is a BOT account; contact import needs a user account"}
        try:
            existing = set(await client(F.contacts.GetContactIDsRequest(hash=0)) or [])
        except _errs() as e:  # noqa: BLE001 — without it we cannot protect pre-existing contacts
            fl = _flood(tl, e)
            return {"error": f"could not list existing contacts ({fl or type(e).__name__}); "
                             f"refusing to import so no pre-existing contact is deleted"}
        for i, phone in enumerate(phones):
            if i and delay:
                await asyncio.sleep(delay)
            cid = random.randrange(1, 2 ** 62)
            row = {"phone": phone, "rung": "lead", "queried": _now()}
            imported_users = []
            try:
                res = await client(F.contacts.ImportContactsRequest(contacts=[T.InputPhoneContact(
                    client_id=cid, phone=phone, first_name="Contact", last_name="")]))
                if cid in (getattr(res, "retry_contacts", None) or []):
                    row.update(found=None, error="import refused (retry_contacts) — per-account import limit")
                    results.append(row)
                    stopped = {"reason": "retry_contacts", "at": phone}
                    break
                ids = {getattr(ic, "user_id", None) for ic in (getattr(res, "imported", None) or [])
                       if getattr(ic, "client_id", None) == cid}
                users = [u for u in (getattr(res, "users", None) or []) if getattr(u, "id", None) in ids]
                imported_users = [u for u in users if u.id not in existing]
                if not users:
                    row.update(found=False, caveat=_caveat("not_found"))
                else:
                    u = users[0]
                    row.update(found=True, caveat=_caveat("phone"), account=_user_row(u),
                               was_existing_contact=u.id in existing)
                    row["account"]["photo"] = await _photo(client, u, save_dir)
            except _errs() as e:  # noqa: BLE001
                fl = _flood(tl, e)
                if fl:
                    row.update(found=None, **fl)
                    results.append(row)
                    stopped = dict(fl, at=phone)
                    break
                row.update(found=None, error=f"{type(e).__name__}: {e}")
            finally:
                if imported_users:
                    try:
                        await client(F.contacts.DeleteContactsRequest(id=imported_users))
                        row["contact_removed"] = True
                    except _errs() as e:  # noqa: BLE001
                        row["contact_removed"] = False
                        errors.append(f"DeleteContacts failed for {phone}: {type(e).__name__}: {e} "
                                      f"— remove it from the research account manually")
            results.append(row)
        return {"research_account": _account_label(meta), "results": results,
                "stopped": stopped, "errors": errors}
    finally:
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass


def phone_lookup(phones, confirm=False, save_photo=None, _client_override=None, _tl_override=None):
    phones = [re.sub(r"[\s().-]", "", p) for p in phones if p and p.strip()]
    bad = [p for p in phones if not _E164.match(p)]
    if bad:
        return {"tool": TOOL, "mode": "phone", "error": f"not E.164 (+<country><number>): {bad}"}
    if not phones:
        return {"tool": TOOL, "mode": "phone", "error": "no phone numbers given"}
    cap = int(SET.get("max_phones_per_run", 10))
    if len(phones) > cap:
        return {"tool": TOOL, "mode": "phone",
                "error": f"{len(phones)} numbers > max_phones_per_run ({cap}); split the batch"}
    if not confirm:
        return briefing(phones)
    if save_photo:
        bad = _unsafe_repo_path(save_photo)
        if bad:
            return {"tool": TOOL, "mode": "phone", "error": bad}
    if _client_override is not None:
        tl, make = _tl_override, (lambda: _client_override)
    else:
        be = _backend()
        if "skipped" in be:
            return dict(be, mode="phone")
        tl = be["tl"]
        make = lambda: _client(be)  # noqa: E731
    try:
        body = asyncio.run(_phone_async(make, tl, phones, save_photo))
    except _errs() as e:  # noqa: BLE001
        body = {"error": f"{type(e).__name__}: {e}"}
    if "skipped" in body:
        return _skip(body["skipped"], mode="phone")
    rows = body.get("results", [])
    _ledger(sum(1 for r in rows if r.get("found") is not None), ",".join(phones),
            sum(1 for r in rows if r.get("found")), "error" not in body)
    out = {"tool": TOOL, "mode": "phone", "sent": True, "rung": "lead", "caveat": _caveat("phone"),
           "partial": bool(body.get("stopped")), "generated": _now()}
    out.update(body)
    return out


def _ledger(n, query, found, ok):
    """Contact imports are quota-limited per research account; record them in the usage ledger
    so the analyst can see how many were spent today. Best-effort."""
    if not n:
        return
    try:
        import api_usage
        api_usage.record("telegram", "contacts.import", credits=n, query=query, results=found, ok=ok)
    except Exception:  # noqa: BLE001
        pass


# --------------------------------------------------------------------------- resolve
def classify_target(target):
    t = (target or "").strip()
    t = re.sub(r"^(?:https?://)?(?:www\.)?", "", t, flags=re.I)
    pats = REF["link_patterns"]
    for kind in ("invite", "private_channel", "peer_id", "username"):
        p = pats.get(kind)
        if not p:
            continue
        m = re.match(p, t, flags=re.I)
        if m:
            return kind, m.group(1)
    return None, t


def _channel_row(ent):
    broadcast = bool(getattr(ent, "broadcast", False))
    return {"type": "channel" if broadcast else ("supergroup" if getattr(ent, "megagroup", False) else
                                                  type(ent).__name__.lower()),
            "id": getattr(ent, "id", None),
            "peer_id": int(f"-100{ent.id}") if type(ent).__name__ == "Channel" else -int(ent.id),
            "title": getattr(ent, "title", None),
            "usernames": _usernames(ent),
            "participants_count": getattr(ent, "participants_count", None),
            "flags": {k: bool(getattr(ent, k, False))
                      for k in ("verified", "scam", "fake", "restricted", "broadcast", "megagroup",
                                "gigagroup", "signatures", "has_link", "noforwards")},
            "restriction_reason": _restrictions(ent),
            "date": _iso(getattr(ent, "date", None)),
            "date_note": "creation date, or the date the research account joined if it is a member"}


async def _resolve_async(make_client, tl, target, save_dir=None):
    F, T = tl["functions"], tl["types"]
    kind, val = classify_target(target)
    row = {"target": target, "kind": kind, "rung": "lead", "caveat": _caveat("resolve"),
           "queried": _now()}
    if kind is None:
        row["error"] = "not a recognisable @username, t.me link, invite link or numeric id"
        return row
    client = make_client()
    await client.connect()
    try:
        if not await client.is_user_authorized():
            return {"skipped": "session present but not authorised — run `login` again"}
        try:
            if kind == "invite":
                inv = await client(F.messages.CheckChatInviteRequest(hash=val))
                chat = getattr(inv, "chat", None)
                if chat is not None:              # ChatInviteAlready / ChatInvitePeek
                    row["entity"] = _channel_row(chat)
                    row["invite"] = {"state": type(inv).__name__}
                else:
                    row["entity"] = {"type": "invite_preview", "title": getattr(inv, "title", None),
                                     "about": getattr(inv, "about", None),
                                     "participants_count": getattr(inv, "participants_count", None),
                                     "flags": {k: bool(getattr(inv, k, False)) for k in
                                               ("channel", "broadcast", "megagroup", "public",
                                                "verified", "scam", "fake", "request_needed")}}
                    row["invite"] = {"state": type(inv).__name__,
                                     "note": "preview only; the research account did NOT join"}
                return row
            if kind == "private_channel":
                ent = await client.get_entity(T.PeerChannel(int(val)))
            elif kind == "peer_id":
                n = int(val)
                ent = await client.get_entity(T.PeerChannel(int(str(n)[4:])) if str(n).startswith("-100")
                                              else T.PeerUser(n))
            else:
                ent = await client.get_entity(val)
            cls = type(ent).__name__
            if cls == "User":
                row["entity"] = _user_row(ent)
                full = await client(F.users.GetFullUserRequest(id=ent))
                fu = getattr(full, "full_user", None)
                row["entity"]["about"] = getattr(fu, "about", None)
                row["entity"]["common_chats_count"] = getattr(fu, "common_chats_count", None)
                row["entity"]["photo"] = await _photo(client, ent, save_dir)
            else:
                row["entity"] = _channel_row(ent)
                if cls == "Channel":
                    full = await client(F.channels.GetFullChannelRequest(channel=ent))
                    fc = getattr(full, "full_chat", None)
                    row["entity"]["about"] = getattr(fc, "about", None)
                    if getattr(fc, "participants_count", None) is not None:
                        row["entity"]["participants_count"] = fc.participants_count
                    row["entity"]["admins_count"] = getattr(fc, "admins_count", None)
                    row["entity"]["linked_chat_id"] = getattr(fc, "linked_chat_id", None)
                row["entity"]["photo"] = await _photo(client, ent, save_dir)
        except _errs() as e:  # noqa: BLE001
            fl = _flood(tl, e)
            row.update(fl or {"error": f"{type(e).__name__}: {e}"})
            if kind in ("peer_id", "private_channel") and not fl:
                row["hint"] = ("a bare numeric id resolves only if the research account has already "
                               "seen that entity; resolve its @username or link instead")
                if kind == "peer_id" and not val.startswith("-"):
                    row["created_estimate"] = estimate_creation(val)
        return row
    finally:
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass


def resolve_briefing(targets, mode="resolve"):
    """What a resolve would send, from which account — offline, nothing is contacted."""
    sess = session_path()
    acct = _account_label(_read_meta(sess))
    fill = {"n": len(targets), "targets": ", ".join(targets), "account": acct, "session": sess}
    lines = []
    for t in REF["resolve_briefing"]:
        try:
            lines.append(t.format(**fill))
        except (KeyError, IndexError, ValueError):
            lines.append(t)
    return {"tool": TOOL, "mode": mode, "confirm_required": True, "sent": False,
            "targets": list(targets), "research_account": acct, "session": sess,
            "session_present": os.path.isfile(sess), "briefing": lines}


def resolve(target, save_photo=None, confirm=False, _client_override=None, _tl_override=None):
    if save_photo:
        bad = _unsafe_repo_path(save_photo)
        if bad:
            return {"tool": TOOL, "mode": "resolve", "error": bad}
    if not confirm:
        return resolve_briefing([target])
    if _client_override is not None:
        tl, make = _tl_override, (lambda: _client_override)
    else:
        be = _backend()
        if "skipped" in be:
            return dict(be, mode="resolve")
        tl = be["tl"]
        make = lambda: _client(be)  # noqa: E731
    try:
        row = asyncio.run(_resolve_async(make, tl, target, save_photo))
    except _errs() as e:  # noqa: BLE001
        row = {"target": target, "error": f"{type(e).__name__}: {e}"}
    if "skipped" in row:
        return _skip(row["skipped"], mode="resolve")
    return {"tool": TOOL, "mode": "resolve", "rung": "lead", "caveat": _caveat("resolve"),
            "generated": _now(), "results": [row]}


# --------------------------------------------------------------------------- age
def _age_summary(row):
    who = row.get("target")
    if row.get("skipped"):
        return f"{who}: not resolved ({row['skipped']})"
    idp = f" → id {row['id']}" if row.get("id") is not None and row.get("kind") != "user_id" else ""
    est = row.get("created_estimate") or {}
    if est.get("estimate"):
        return (f"{who}{idp}: created ≈ {est['month']} ({est['range']['from']} … "
                f"{est['range']['to']}, ±{est['error_days']} d, {est['confidence']} confidence"
                f"{', extrapolated' if est.get('extrapolated') else ''}); age {est['age']}")
    if (row.get("created") or {}).get("date"):
        return f"{who}{idp}: {row.get('type')} dated {row['created']['date']} by Telegram"
    return f"{who}{idp}: {row.get('error') or est.get('error') or 'no date available'}"


def _age_row(target, kind, res):
    """One `age` row from a resolve() payload: the id plus the creation date — estimated from the
    id for a user/bot, Telegram's own `date` for a channel/group."""
    row = {"target": target, "kind": kind, "rung": "lead"}
    if res.get("skipped") or res.get("error"):
        row.update({k: res[k] for k in ("skipped", "error") if res.get(k)})
        row["summary"] = _age_summary(row)
        return row
    r = (res.get("results") or [{}])[0]
    row.update({k: r[k] for k in ("error", "seconds", "hint", "created_estimate") if r.get(k) is not None})
    ent = r.get("entity") or {}
    if ent:
        name = " ".join(x for x in (ent.get("first_name"), ent.get("last_name")) if x)
        row.update(source="resolve (research account)", type=ent.get("type"), id=ent.get("id"),
                   usernames=[u.get("username") for u in ent.get("usernames") or []
                              if isinstance(u, dict) and u.get("username")],
                   name=name or ent.get("title"))
        if ent.get("peer_id") is not None:
            row["peer_id"] = ent["peer_id"]
        if ent.get("type") in ("user", "bot") and ent.get("id") is not None:
            row["created_estimate"] = ent.get("created_estimate") or estimate_creation(ent["id"])
        elif ent.get("date"):
            row["created"] = {"date": ent["date"], "source": "telegram", "note": ent.get("date_note")}
    row["summary"] = _age_summary(row)
    return row


def age(targets, confirm=False, _client_override=None, _tl_override=None):
    """@username / t.me link / numeric user id → id + creation date. A positive numeric id is dated
    offline; anything else is resolved first (one ResolveUsername each, capped per call) and only
    with `confirm` — without it those targets get a briefing and nothing is sent."""
    targets = [str(t).strip() for t in targets or [] if t and str(t).strip()]
    kinds = [classify_target(t) for t in targets]
    online = sum(1 for k, v in kinds if k is not None and not (k == "peer_id" and not v.startswith("-")))
    cap = int(SET.get("max_resolve_per_run", 10))
    if online > cap:
        return {"tool": TOOL, "mode": "age",
                "error": f"{online} targets need a Telegram resolve; at most {cap} per call "
                         f"(settings.max_resolve_per_run) — split the batch"}
    results = []
    for t, (kind, val) in zip(targets, kinds):
        if kind == "peer_id" and not val.startswith("-"):
            row = {"target": t, "kind": "user_id", "rung": "lead", "id": int(val),
                   "source": "offline (id → date curve; no Telegram call)",
                   "created_estimate": estimate_creation(val)}
            row["summary"] = _age_summary(row)
        elif kind is None:
            row = {"target": t, "kind": None, "rung": "lead",
                   "error": "not a recognisable @username, t.me link, invite link or numeric id"}
            row["summary"] = _age_summary(row)
        elif not confirm:
            row = {"target": t, "kind": kind, "rung": "lead", "awaiting_confirm": True,
                   "summary": f"{t}: not sent — resolving it runs on the research account; "
                              f"re-run with --confirm after the analyst approves"}
        else:
            row = _age_row(t, kind, resolve(t, confirm=True, _client_override=_client_override,
                                            _tl_override=_tl_override))
        results.append(row)
    out = {"tool": TOOL, "mode": "age", "rung": "lead",
           "caveat": f"{_caveat('resolve')} {CAV.get('age', '')}".strip(),
           "generated": _now(), "results": results}
    pending = [r["target"] for r in results if r.get("awaiting_confirm")]
    if pending:
        out.update({k: v for k, v in resolve_briefing(pending, mode="age").items()
                    if k in ("confirm_required", "sent", "research_account", "session",
                             "session_present", "briefing")})
    skipped = [r for r in results if r.get("skipped")]
    if skipped:
        out["setup"] = list(REF["setup"])
        if len(skipped) == len(results):
            out["skipped"] = skipped[0]["skipped"]
    return out



# --------------------------------------------------------------------------- status / login
def _auth_row(a):
    return {"device_model": getattr(a, "device_model", None), "platform": getattr(a, "platform", None),
            "system_version": getattr(a, "system_version", None),
            "app_name": getattr(a, "app_name", None), "app_version": getattr(a, "app_version", None),
            "official_app": bool(getattr(a, "official_app", False)),
            "date_created": _iso(getattr(a, "date_created", None)),
            "date_active": _iso(getattr(a, "date_active", None)),
            "ip": getattr(a, "ip", None) or None, "country": getattr(a, "country", None) or None,
            "region": getattr(a, "region", None) or None,
            "current": bool(getattr(a, "current", False)),
            "password_pending": bool(getattr(a, "password_pending", False))}


async def _sessions_async(client, tl):
    """Read-only: the research account's active authorisations + opentele2's consistency checks.
    Nothing here terminates or changes a session."""
    out = {}
    try:
        auths = await client(tl["functions"].account.GetAuthorizationsRequest())
        out["sessions"] = [_auth_row(a) for a in (getattr(auths, "authorizations", None) or [])]
    except _errs() as e:  # noqa: BLE001
        out["sessions"] = {"error": f"{type(e).__name__}: {e}"}
    if hasattr(client, "RunConsistencyChecks"):
        try:
            rep = await client.RunConsistencyChecks(auto_warn=False)
            checks = [{"name": getattr(c, "name", None), "ok": bool(getattr(c, "passed", False)),
                       "detail": getattr(c, "detail", "")} for c in (getattr(rep, "checks", None) or [])]
            out["consistency"] = {"all_passed": all(c["ok"] for c in checks) if checks else None,
                                  "checks": checks}
        except _errs() as e:  # noqa: BLE001
            out["consistency"] = {"error": f"{type(e).__name__}: {e}"}
    else:
        out["consistency"] = {"skipped": "consistency checks need the opentele2 backend"}
    return out


def status(sessions=False, _client_override=None, _be_override=None):
    sess = session_path()
    tl, ot = _import_telethon(), _import_opentele2()
    meta = _read_meta(sess) if os.path.isfile(sess) else None
    out = {"tool": TOOL, "mode": "status", "telethon_installed": tl is not None,
           "telethon_version": tl["version"] if tl else None,
           "opentele2_installed": ot is not None, "opentele2_version": ot["version"] if ot else None,
           "api_credentials_set": _creds() is not None, "session": sess,
           "session_present": os.path.isfile(sess), "backend": (meta or {}).get("backend"),
           "profile": (meta or {}).get("profile"), "device": None, "authorised": None,
           "research_account": _account_label(meta) if meta else None}
    if meta and meta.get("api"):
        out["device"] = {k: meta["api"].get(k) for k in ("api_id", "device_model", "system_version",
                                                          "app_version")}
    be = _be_override if _be_override is not None else _backend()
    if "skipped" in be:
        out["backend_problem"] = be["skipped"]
        out["setup"] = list(REF["setup"])
        return out
    out["backend"], out["profile"] = be["backend"], be["profile"]

    async def _chk():
        client = _client_override if _client_override is not None else _client(be)
        await client.connect()
        try:
            ok = await client.is_user_authorized()
            me = await client.get_me() if ok else None
            extra = await _sessions_async(client, be["tl"]) if (ok and sessions) else None
            return ok, me, extra
        finally:
            await client.disconnect()
    try:
        ok, me, extra = asyncio.run(_chk())
        out["authorised"] = bool(ok)
        if me is not None:
            out["research_account"] = _account_label(_write_meta(sess, me, {"backend": be["backend"]}))
        if extra:
            out.update(extra)
    except _errs() as e:  # noqa: BLE001
        out["error"] = f"{type(e).__name__}: {e}"
    return out


def _identity(be):
    """Fix the api + device for this session ONCE, at login, and return the sidecar fields that
    make every later connection reuse it. A re-login into an existing session keeps its device."""
    if be["backend"] != "opentele2":
        return {"backend": "telethon", "api_id": be["creds"][0]}
    meta = be.get("meta") or {}
    if meta.get("api"):
        be["api"] = _api_from_meta(be["ot"], meta)
        return {"backend": "opentele2", "profile": meta.get("profile"),
                "unique_id": meta.get("unique_id"), "api": meta["api"]}
    uid = secrets.token_hex(16)
    be["api"] = generate_api(be["ot"], be["profile"], uid)
    return {"backend": "opentele2", "profile": be["profile"], "unique_id": uid,
            "api": api_snapshot(be["api"])}


def _qr_presenter(stream=None):
    """(show(url, n) -> png_path_or_None, cleanup()). Terminal QR when `qrcode` is importable, a
    PNG in a private temp dir when qrcode + Pillow are; the URL is always printed. The PNG is a live
    login token for its lifetime, so cleanup() deletes it whatever happens."""
    stream = stream or sys.stderr
    state = {"dir": None}

    def show(url, n):
        print(f"\n[QR {n + 1}] In the RESEARCH account's Telegram app: Settings → Devices → "
              f"Link Desktop Device, then scan. Login URL:\n{url}\n", file=stream)
        try:
            import qrcode
        except ImportError:
            print("(pip install qrcode for a terminal QR; qrcode + pillow for a PNG)", file=stream)
            return None
        try:
            q = qrcode.QRCode(border=1)
            q.add_data(url)
            q.make(fit=True)
            q.print_ascii(out=stream, invert=True)
        except Exception:  # noqa: BLE001
            pass
        try:
            import PIL  # noqa: F401
            if state["dir"] is None:
                state["dir"] = tempfile.mkdtemp(prefix=str(SET.get("qr_png_prefix", "cti-tgqr-")))
                if _unsafe_repo_path(state["dir"]):
                    return None
            p = os.path.join(state["dir"], f"qr-{n + 1}.png")
            qrcode.make(url).save(p)
            os.chmod(p, 0o600)
            print(f"QR PNG (deleted after login): {p}", file=stream)
            return p
        except Exception:  # noqa: BLE001
            return None

    def cleanup():
        if state["dir"]:
            shutil.rmtree(state["dir"], ignore_errors=True)
    return show, cleanup


async def qr_flow(client, tl, getpass_fn, show_fn, wait=None, max_recreate=None):
    """Telethon QR login: show tg://login?token=…, wait, re-create on expiry, 2FA via getpass_fn.
    Returns (me, info)."""
    wait = int(SET.get("qr_wait_seconds", 120) if wait is None else wait)
    max_recreate = int(SET.get("qr_max_recreate", 3) if max_recreate is None else max_recreate)
    spn = getattr(tl["errors"], "SessionPasswordNeededError", None)
    await client.connect()
    try:
        if await client.is_user_authorized():
            return await client.get_me(), {"already_authorised": True}
        qr = await client.qr_login()
        shown = 0
        while True:
            show_fn(qr.url, shown)
            shown += 1
            try:
                # A login token dies at qr.expires (Telegram issues ~30 s tokens): waiting past it
                # leaves a stale code on screen that can no longer be scanned, so re-create then.
                left = wait
                exp = getattr(qr, "expires", None)
                if exp is not None:
                    try:
                        left = min(wait, max(1, int((exp - datetime.datetime.now(datetime.timezone.utc)).total_seconds())))
                    except (TypeError, ValueError):
                        left = wait
                await qr.wait(timeout=left)
                break
            except (asyncio.TimeoutError, TimeoutError):
                if shown > max_recreate:
                    raise TimeoutError(f"QR code not scanned after {shown} code(s)")
                await qr.recreate()
            except Exception as e:  # noqa: BLE001
                if spn is not None and isinstance(e, spn):
                    await client.sign_in(password=getpass_fn("Telegram 2FA password (hidden): "))
                    break
                raise
        return await client.get_me(), {"qr_codes_shown": shown}
    finally:
        try:
            await client.disconnect()
        except _errs():  # noqa: BLE001
            pass


def tdata_refusal(path, own_account):
    """Reason string when a tdata import must be refused, else None. tdata is a full session of a
    desktop install: import only the analyst's OWN research install — never case material or a
    stealer-log dump (using a victim's session is account takeover, not OSINT)."""
    if not own_account:
        return ("refused: tdata import requires --own-account — only the analyst's own research "
                "Telegram Desktop install; never a tdata from a case, a seized device or a stealer log")
    if not path or not os.path.isdir(path):
        return f"refused: {path!r} is not a directory"
    rp = os.path.realpath(path)
    repo = os.path.realpath(REPO)
    if rp == repo or rp.startswith(repo + os.sep):
        return "refused: the tdata directory is inside the skill repo"
    home_cases = os.path.realpath(os.path.join(os.environ.get("INTEL_HOME") or ENGINE, "cases"))
    if rp == home_cases or rp.startswith(home_cases + os.sep):
        return "refused: the tdata directory is inside the case store ($INTEL_HOME/cases)"
    if any(part.lower() == "cases" for part in rp.split(os.sep)):
        return "refused: the tdata directory is under a `cases/` path (case material)"
    markers = {m.lower().rstrip("/") for m in REF.get("stealer_log_markers") or []}
    d = rp
    for _ in range(3):                         # the dir itself, its parent, its grandparent
        try:
            hits = sorted(n for n in os.listdir(d) if n.lower() in markers)
        except OSError:
            hits = []
        if hits:
            return (f"refused: {d} contains {', '.join(hits)} — this looks like a stealer-log dump, "
                    f"not the analyst's own install")
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return None


def _needs_password(e):
    return type(e).__name__ in ("NoPasswordProvided", "SessionPasswordNeededError")


async def _tdata_flow(be, tdesk, flag, api, getpass_fn):
    pw = None
    client = None
    for attempt in range(2):
        try:
            client = await be["ot"]["TelegramClient"].FromTDesktop(
                tdesk, session=be["sess"], flag=flag, api=api, password=pw, **_client_kwargs(be))
            break
        except _errs() as e:  # noqa: BLE001
            if attempt == 0 and _needs_password(e):
                pw = getpass_fn("2FA password of the account in this tdata (hidden): ")
                continue
            raise
    try:
        if not client.is_connected():
            await client.connect()
        return await client.get_me()
    finally:
        try:
            await client.disconnect()
        except _errs():  # noqa: BLE001
            pass


def _login_tdata(tdata, own_account, passcode_prompt, reuse_desktop_session, profile,
                 getpass_fn=None):
    getpass_fn = getpass_fn or getpass.getpass
    reason = tdata_refusal(tdata, own_account)
    if reason:
        return {"tool": TOOL, "mode": "login", "refused": True, "error": reason}
    be = _backend(profile=profile, need_session=False, force_opentele2=True)
    if "skipped" in be:
        return dict(be, mode="login")
    if os.path.isfile(be["sess"]):
        return {"tool": TOOL, "mode": "login", "error": f"a session already exists at {be['sess']}; "
                "a tdata import writes a NEW session — point TELEGRAM_SESSION at a fresh path"}
    os.makedirs(os.path.dirname(be["sess"]), mode=0o700, exist_ok=True)
    ot = be["ot"]
    passcode = getpass_fn("Telegram Desktop local passcode (hidden): ") if passcode_prompt else None
    try:
        tdesk = ot["TDesktop"](tdata, passcode=passcode)
    except _errs() as e:  # noqa: BLE001 — TFileNotFound etc. are BaseException subclasses
        return {"tool": TOOL, "mode": "login", "error": f"could not load tdata: {type(e).__name__}: {e}"}
    warning = None
    if reuse_desktop_session:
        flag, api = ot["UseCurrentSession"], tdesk.api
        extra = {"backend": "opentele2", "profile": "desktop", "unique_id": None,
                 "api": api_snapshot(api), "origin": "tdata-shared-auth-key"}
        warning = ("--reuse-desktop-session: this tool and the desktop app now share ONE auth key; "
                   "terminating either session logs out both, and concurrent use from two egress "
                   "addresses is visible to Telegram")
        print(f"WARNING: {warning}", file=sys.stderr)
    else:
        flag = ot["CreateNewSession"]
        uid = secrets.token_hex(16)
        api = generate_api(ot, be["profile"], uid)
        extra = {"backend": "opentele2", "profile": be["profile"], "unique_id": uid,
                 "api": api_snapshot(api), "origin": "tdata-new-session"}
    try:
        me = asyncio.run(_tdata_flow(be, tdesk, flag, api, getpass_fn))
    except _errs() as e:  # noqa: BLE001
        return {"tool": TOOL, "mode": "login", "error": f"{type(e).__name__}: {e}"}
    return _login_done(be, me, extra, {"method": "tdata", "warning": warning} if warning
                       else {"method": "tdata"})


def _login_done(be, me, extra, info):
    try:
        os.chmod(be["sess"], 0o600)
    except OSError:
        pass
    meta = _write_meta(be["sess"], me, extra)
    out = {"tool": TOOL, "mode": "login", "authorised": True, "session": be["sess"],
           "backend": meta.get("backend"), "profile": meta.get("profile"),
           "research_account": _account_label(meta)}
    out.update({k: v for k, v in (info or {}).items() if v is not None})
    if meta.get("bot"):
        out["warning"] = "this is a BOT session; `phone` (contact import) will not work with it"
    return out


def login(qr=False, profile=None, tdata=None, own_account=False, passcode_prompt=False,
          reuse_desktop_session=False):
    """Interactive only. Phone-code (default) and QR use the analyst's TTY for every secret; tdata
    imports the analyst's own desktop install. No code/password/passcode is ever an argument."""
    if not sys.stdin.isatty():
        return _skip("login is interactive — run it yourself in a terminal; the tool never accepts a "
                     "login code or password as an argument", mode="login")
    if tdata is not None:
        return _login_tdata(tdata, own_account, passcode_prompt, reuse_desktop_session, profile)
    be = _backend(profile=profile, need_session=False)
    if "skipped" in be:
        return dict(be, mode="login")
    os.makedirs(os.path.dirname(be["sess"]), mode=0o700, exist_ok=True)
    fresh = not os.path.isfile(be["sess"])

    def _drop_unauthorised():
        # A failed/abandoned first login leaves an UNAUTHORISED auth key with no sidecar; the next
        # login would reuse that key under a newly generated device. Remove it so retries start clean.
        if fresh and not os.path.isfile(_meta_path(be["sess"])):
            for p in (be["sess"], be["sess"] + "-journal"):
                try:
                    os.remove(p)
                except OSError:
                    pass
    extra = _identity(be)
    print(f"Log in with the RESEARCH account (not a personal one). Backend: {be['backend']}"
          + (f", profile {be['profile']}" if be["profile"] else "") + ".", file=sys.stderr)
    if qr:
        show, cleanup = _qr_presenter()

        async def _go():
            return await qr_flow(_client(be), be["tl"], getpass.getpass, show)
        try:
            me, info = asyncio.run(_go())
        except _errs() as e:  # noqa: BLE001
            _drop_unauthorised()
            return {"tool": TOOL, "mode": "login", "error": f"{type(e).__name__}: {e}"}
        except KeyboardInterrupt:
            _drop_unauthorised()
            raise
        finally:
            cleanup()
        return _login_done(be, me, extra, dict(info, method="qr"))
    print("Telethon will prompt for the phone number, the login code Telegram sends, and a 2FA "
          "password if set.", file=sys.stderr)

    async def _go_code():
        client = _client(be)
        await client.start()
        try:
            return await client.get_me()
        finally:
            await client.disconnect()
    try:
        me = asyncio.run(_go_code())
    except _errs() as e:  # noqa: BLE001
        _drop_unauthorised()
        return {"tool": TOOL, "mode": "login", "error": f"{type(e).__name__}: {e}"}
    except KeyboardInterrupt:
        _drop_unauthorised()
        raise
    return _login_done(be, me, extra, {"method": "code"})


# --------------------------------------------------------------------------- CLI
def _save_case(case, payload):
    if not case or not re.match(r"^[A-Za-z0-9._-]+$", case):
        return None
    d = os.path.join(ENGINE, "cases", case, "telegram")
    try:
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, f"{payload.get('mode')}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        return p
    except OSError:
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(description="Telegram phone/username → account LEAD lookup (Telethon).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    lg = sub.add_parser("login", help="interactive login with the research account")
    lg.add_argument("--qr", action="store_true",
                    help="scan a QR code with the research account's phone instead of a login code")
    lg.add_argument("--profile", choices=sorted(_profiles()),
                    help="opentele2 device profile (official app api_id + device); fixed at login")
    lg.add_argument("--tdata", metavar="DIR",
                    help="import the analyst's OWN Telegram Desktop tdata (needs --own-account)")
    lg.add_argument("--own-account", action="store_true",
                    help="attest the tdata is the analyst's own research install")
    lg.add_argument("--passcode-prompt", action="store_true",
                    help="prompt (hidden) for the Telegram Desktop local passcode")
    lg.add_argument("--reuse-desktop-session", action="store_true",
                    help="share the desktop app's auth key instead of creating a new session")
    st = sub.add_parser("status", help="session/credential status (no secrets printed)")
    st.add_argument("--sessions", action="store_true",
                    help="also list the account's active sessions + opentele2 consistency checks")
    p = sub.add_parser("phone", help="E.164 number(s) → account (contact import; needs --confirm-import)")
    p.add_argument("phones", nargs="+")
    p.add_argument("--confirm-import", action="store_true", help="actually send the import (else: briefing)")
    p.add_argument("--save-photo", metavar="DIR")
    p.add_argument("--case")
    r = sub.add_parser("resolve", help="@username | t.me link | invite | -100id → public metadata")
    r.add_argument("target")
    r.add_argument("--confirm", action="store_true", help="actually send the resolve (else: briefing)")
    r.add_argument("--save-photo", metavar="DIR")
    r.add_argument("--case")
    ag = sub.add_parser("age", help="@username | t.me link | user id → id + estimated creation date")
    ag.add_argument("targets", nargs="+")
    ag.add_argument("--confirm", action="store_true",
                    help="actually resolve @usernames/links (else: briefing; numeric ids are offline)")
    ag.add_argument("--case")
    a = ap.parse_args(argv)
    if a.cmd == "login":
        out = login(qr=a.qr, profile=a.profile, tdata=a.tdata, own_account=a.own_account,
                    passcode_prompt=a.passcode_prompt,
                    reuse_desktop_session=a.reuse_desktop_session)
    elif a.cmd == "status":
        out = status(sessions=a.sessions)
    elif a.cmd == "phone":
        out = phone_lookup(a.phones, confirm=a.confirm_import, save_photo=a.save_photo)
    elif a.cmd == "age":
        out = age(a.targets, confirm=a.confirm)
    else:
        out = resolve(a.target, save_photo=a.save_photo, confirm=a.confirm)
    if getattr(a, "case", None) and out.get("results"):
        saved = _save_case(a.case, out)
        if saved:
            out["saved"] = saved
    print(json.dumps(out, indent=2, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
