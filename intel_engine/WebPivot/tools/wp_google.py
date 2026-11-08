#!/usr/bin/env python3
"""GHunt 2 email/Gaia adapter; all account data is an uncorroborated lead.

Uses only the session created by `ghunt login`; never accepts credentials.
GHunt performs its own authenticated transport; this adapter performs no HTTP.
Schema: GHunt modules/email.py, modules/gaia.py, parsers/people.py and
objects/encoders.py (https://github.com/mxrch/GHunt, inspected version 2.3.4).
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
from urllib.parse import quote

try:
    from .wp_refs import load_ref, ref_path
except ImportError:
    from wp_refs import load_ref, ref_path

_FALLBACK = {
    "settings": {"timeout_seconds": 180},
    "binaries": ["ghunt"],
    "session_files": ["~/.malfrats/ghunt/creds.m"],
    "setup": ["pipx install ghunt", "ghunt login (analyst's research Google account)"],
    "endpoints": {"maps_contrib": "https://www.google.com/maps/contrib/{gaia}/reviews"},
    "account_kinds": {"GOOGLE_APPS_USER": "workspace", "GOOGLE_USER": "personal"},
    "caveats": {"overall": "Account data is a lead, not identity or operator attribution.",
                "maps_contrib": "A review location indicates a place visited, not residence."},
}
_REFS = load_ref(ref_path(__file__, "google_account.json"), _FALLBACK)


def _dict(value):
    return value if isinstance(value, dict) else {}


def _url(key, **values):
    template = _REFS["endpoints"].get(key, "")
    for name, value in values.items():
        template = template.replace("{" + name + "}", quote(str(value), safe=""))
    return template or None


def _lead(kind, value):
    return {"type": kind, "value": value, "rung": "lead",
            "caveat": _REFS["caveats"].get(kind, _REFS["caveats"]["overall"])}


def _base(query, mode):
    gaia = query if mode == "gaia" else None
    maps = {"contributions_url": _url("maps_contrib", gaia=gaia) if gaia else None,
            "stats": None}
    return {"query": query, "mode": mode, "source": "GHunt", "rung": "lead",
            "caveat": _REFS["caveats"]["overall"], "gaia_id": gaia,
            "profile_name": None, "profile_photo": None, "cover_photo": None,
            "last_profile_edit": None, "maps": maps, "calendar_public": None,
            "play_games": None, "youtube_channel_guess": None,
            "enabled_services": None, "account_type": "unknown", "leads": []}


def map_ghunt(data, query="", mode="email"):
    """Map GHuntEncoder PROFILE_CONTAINER data; absent is unknown, not false."""
    out = _base(query, mode)
    container = _dict(_dict(data).get("PROFILE_CONTAINER"))
    profile = _dict(container.get("profile"))
    if not profile:
        out["error"] = "GHunt JSON has no PROFILE_CONTAINER.profile; unsupported or absent public profile"
        return out
    out["gaia_id"] = str(profile.get("personId") or out["gaia_id"] or "") or None
    def field(name):
        return _dict(_dict(profile.get(name)).get("PROFILE"))
    out["profile_name"] = field("names").get("fullname") or None
    for src, dst in (("profilePhotos", "profile_photo"), ("coverPhotos", "cover_photo")):
        item = field(src)
        if item:
            out[dst] = {"url": item.get("url") or None, "is_default": item.get("isDefault")}
    out["last_profile_edit"] = field("sourceIds").get("lastUpdated") or None
    out["enabled_services"] = field("inAppReachability").get("apps")
    types = field("profileInfos").get("userTypes") or []
    extended = _dict(profile.get("extendedData"))
    customer = _dict(extended.get("dynamiteData")).get("customerId")
    enterprise = _dict(extended.get("gplusData")).get("isEntrepriseUser")
    kinds = [_REFS["account_kinds"].get(t) for t in types if isinstance(t, str)]
    if customer or enterprise is True or "workspace" in kinds:
        out["account_type"] = "workspace"
    elif "personal" in kinds:
        out["account_type"] = "personal"
    elif any(k and k.startswith("personal") for k in kinds):
        out["account_type"] = "personal"
    if out["gaia_id"]:
        out["maps"]["contributions_url"] = _url("maps_contrib", gaia=out["gaia_id"])
    # GHunt uses capitalised Google Maps labels, not lower-case API keys.
    raw_stats = _dict(_dict(container.get("maps")).get("stats"))
    out["maps"]["stats"] = {k.lower(): v for k, v in raw_stats.items()
                                if isinstance(v, (int, float)) and not isinstance(v, bool)} or None
    # Gaia mode never runs Calendar/Play Games. Missing key remains unknown.
    if "calendar" in container:
        out["calendar_public"] = isinstance(container["calendar"], dict)
    player = _dict(_dict(container.get("play_games")).get("profile"))
    if player:
        out["play_games"] = {k: player.get(k) for k in
                             ("id", "display_name", "gamertag", "avatar_url")}
    if out["profile_name"]:
        out["youtube_channel_guess"] = {
            "search_url": _url("youtube_channel_search", q=out["profile_name"]),
            "channel_url": None, "verified": False,
            "caveat": _REFS["caveats"].get("youtube", _REFS["caveats"]["overall"])}
    for key in ("gaia_id", "profile_name", "profile_photo", "cover_photo", "last_profile_edit"):
        if out[key] is not None:
            out["leads"].append(_lead(key, out[key]))
    for kind, value in (("maps_contrib", out["maps"]["contributions_url"]),
                        ("maps_stats", out["maps"]["stats"]),
                        ("calendar", out["calendar_public"]),
                        ("play_games", out["play_games"]),
                        ("youtube", out["youtube_channel_guess"]),
                        ("services", out["enabled_services"]), ("workspace_customer", customer),
                        ("account_type", out["account_type"])):
        if value is not None:
            out["leads"].append(_lead(kind, value))
    return out


def _command():
    override = os.environ.get(_REFS["settings"].get("bin_env", "GHUNT_BIN"))
    if override:
        executable = shutil.which(override)
        return [executable] if executable else None
    for name in _REFS["binaries"]:
        executable = shutil.which(name)
        if executable:
            return [executable]
    if importlib.util.find_spec("ghunt") is not None:
        return [sys.executable, "-c", "from ghunt.ghunt import main; main()"]
    return None


def lookup(query, mode="auto", dry_run=False, timeout=None):
    """Return data, skipped/setup, or error; never expose GHunt stdout/session data."""
    query = str(query).strip()
    if mode == "auto":
        mode = "email" if "@" in query else "gaia"
    out = _base(query, mode)
    if mode not in ("email", "gaia") or not query or query.startswith("-"):
        return dict(out, error="Expected an email address or Gaia ID")
    if mode == "gaia" and not query.isdecimal():
        return dict(out, error="Gaia ID must contain digits only")
    if mode == "email" and (query.count("@") != 1 or any(c.isspace() for c in query)):
        return dict(out, error="Expected an email address")
    if out["maps"]["contributions_url"]:
        out["leads"].append(_lead("maps_contrib", out["maps"]["contributions_url"]))
    try:
        command = _command()
        if command is None:
            return dict(out, skipped="GHunt not installed or executable unavailable", setup=_REFS["setup"])
        # Presence only: no session bytes are ever opened or returned by this wrapper.
        logged_in = any(Path(p).expanduser().is_file() and Path(p).expanduser().stat().st_size > 0
                        for p in _REFS["session_files"])
        if not logged_in:
            return dict(out, skipped="No GHunt login session found", setup=_REFS["setup"])
        if dry_run:
            return dict(out, dry_run=True, session_present=True,
                        argv=command + [mode, query, "--json", "<temporary-output.json>"],
                        note="No network lookup performed; session presence does not prove session validity")
        duration = float(timeout if timeout is not None else _REFS["settings"]["timeout_seconds"])
        if duration <= 0:
            return dict(out, error="timeout must be positive")
        with tempfile.TemporaryDirectory(prefix="wp-google-") as directory:
            path = Path(directory) / "result.json"
            result = subprocess.run(command + [mode, query, "--json", str(path)],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=duration, check=False)
            # Provider logs can contain sensitive session diagnostics; never forward them.
            if result.returncode != 0:
                return dict(out, error="GHunt failed; session may be expired or provider unavailable",
                            setup=_REFS["setup"], returncode=result.returncode)
            if not path.is_file():
                return dict(out, result=None,
                            note="GHunt returned no JSON: no public profile, or provider/authentication failure; not proof the account is absent")
            with path.open(encoding="utf-8") as handle:
                return map_ghunt(json.load(handle), query, mode)
    except subprocess.TimeoutExpired:
        return dict(out, error="GHunt lookup timed out")
    except (OSError, ValueError, TypeError, ImportError) as exc:
        return dict(out, error="GHunt wrapper failure: " + type(exc).__name__)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("query", help="Email address or Gaia ID")
    parser.add_argument("--mode", choices=("auto", "email", "gaia"), default="auto")
    parser.add_argument("--dry-run", action="store_true", help="Detect installation/session without querying Google")
    parser.add_argument("--input-json", help="Map saved GHunt JSON offline; performs no lookup")
    parser.add_argument("--timeout", type=float)
    parser.add_argument("--json", action="store_true", help="Compact JSON output")
    args = parser.parse_args()
    if args.input_json:
        try:
            with open(args.input_json, encoding="utf-8") as handle:
                mode = args.mode if args.mode != "auto" else ("email" if "@" in args.query else "gaia")
                result = map_ghunt(json.load(handle), args.query, mode)
        except (OSError, ValueError, TypeError) as exc:
            result = {"error": "Cannot map saved GHunt JSON: " + type(exc).__name__}
    else:
        result = lookup(args.query, args.mode, args.dry_run, args.timeout)
    print(json.dumps(result, ensure_ascii=False, indent=None if args.json else 2))
    return 1 if result.get("error") else 0


if __name__ == "__main__":
    sys.exit(main())
