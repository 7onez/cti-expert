"""wp_subenum — subdomain enumeration for a seed apex via the installed passive tools, keyed from .env.

Runs whichever of subfinder / amass (passive) / assetfinder / findomain is installed — searched on
PATH, in ~/go/bin and in an Osmedeus `external-binaries` tree — unions the names, DNS-verifies them
and writes cases/<case>/subenum/<apex>.json. `case_state.frontier()` reads that file and queues the
LIVE subdomains of a collected apex for next-round collection exactly like the apex (same
registration = rung-1 join on `apex:<registrable>` at ingest).

Keys: subfinder reads ~/.config/subfinder/provider-config.yaml. Before each run this module syncs
that file from the skill's .env — filling ONLY providers whose entry is empty, never overwriting a
key the analyst set by hand, never printing a value. Mapping (subfinder id ← env names):

    shodan ← SHODAN_KEY / SHODAN_API_KEY          securitytrails ← SECURITYTRAILS_API_KEY
    censys ← CENSYS_API_ID:CENSYS_API_SECRET       whoisxmlapi    ← WHOISXML_API_KEY
    fofa   ← FOFA_EMAIL:FOFA_KEY                   certspotter    ← CERTSPOTTER_API_KEY
    intelx ← INTELX_HOST:INTELX_KEY (host default 2.intelx.io)   github ← GITHUB_TOKEN
    netlas ← NETLAS_API_KEY                         virustotal    ← VIRUSTOTAL_API_KEY / VT_API_KEY
    zoomeyeapi ← ZOOMEYE_API_KEY                    quake         ← QUAKE_API_KEY
    chaos ← CHAOS_KEY / PDCP_API_KEY                hunter is NOT a subfinder source (Hunter.how runs in wp_hunterhow)
    bevigil / fullhunt / leakix / dnsdb / c99 / redhuntlabs / threatbook / builtwith / robtex / digitalyama /
    dnsrepo ← <ID>_API_KEY

Stdlib only; the tools are external binaries and every one of them degrades to "not installed".
"""
import os
import re
import sys
import json
import glob
import shutil
import socket
import argparse
import datetime
import subprocess
import concurrent.futures

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))            # intel_engine/
SKILL = os.path.abspath(os.path.join(ROOT, ".."))                 # skill root (holds .env)

# Per-call ceiling for the subfinder/amass enumeration subprocess — ONE resolver (wp_timeouts:
# env CTI_CALL_TIMEOUT → .env → references/timeouts.json → 1800s / 30 min).
sys.path.insert(0, HERE)
from wp_timeouts import CALL_TIMEOUT, floor as _floor  # noqa: E402

_TOOL_DIRS = [os.path.expanduser("~/go/bin"), os.path.expanduser("~/.local/bin"), "/usr/local/bin"]
_TOOL_DIRS += glob.glob(os.path.expanduser("~/osmedeus-base/external-binaries"))
_TOOL_DIRS += glob.glob("/opt/osmedeus*/external-binaries")

# subfinder provider id -> (env names, joiner) ; a tuple of env names is joined with ":" (id:secret)
_PROVIDER_ENV = {
    "shodan": (("SHODAN_KEY", "SHODAN_API_KEY"), None),
    "securitytrails": (("SECURITYTRAILS_API_KEY",), None),
    "whoisxmlapi": (("WHOISXML_API_KEY", "WHOISXMLAPI_KEY"), None),
    "certspotter": (("CERTSPOTTER_API_KEY",), None),
    "github": (("GITHUB_TOKEN", "GH_TOKEN"), None),
    "netlas": (("NETLAS_API_KEY",), None),
    "virustotal": (("VIRUSTOTAL_API_KEY", "VT_API_KEY"), None),
    "zoomeyeapi": (("ZOOMEYE_API_KEY",), None),
    "quake": (("QUAKE_API_KEY",), None),
    "chaos": (("CHAOS_KEY", "PDCP_API_KEY"), None),
    "bevigil": (("BEVIGIL_API_KEY",), None),
    "fullhunt": (("FULLHUNT_API_KEY",), None),
    "leakix": (("LEAKIX_API_KEY",), None),
    "dnsdb": (("DNSDB_API_KEY",), None),
    "c99": (("C99_API_KEY",), None),
    "redhuntlabs": (("REDHUNT_API_KEY", "REDHUNTLABS_API_KEY"), None),
    "threatbook": (("THREATBOOK_API_KEY",), None),
    "builtwith": (("BUILTWITH_API_KEY",), None),
    "robtex": (("ROBTEX_API_KEY",), None),
    "digitalyama": (("DIGITALYAMA_API_KEY",), None),
    "dnsrepo": (("DNSREPO_API_KEY",), None),
    # composite credentials
    "censys": (("CENSYS_API_ID", "CENSYS_API_SECRET"), ":"),
    "fofa": (("FOFA_EMAIL", "FOFA_KEY"), ":"),
    "intelx": (("INTELX_HOST", "INTELX_KEY", "INTELX_API_KEY"), "intelx"),
}


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_env(path=None):
    """Skill .env as a dict (process env wins). Values never leave this process."""
    env = dict(os.environ)
    p = path or os.environ.get("CTI_API_KEYS_ENV") or os.path.join(SKILL, ".env")
    try:
        for ln in open(p, encoding="utf-8"):
            ln = ln.strip()
            if not ln or ln.startswith("#") or "=" not in ln:
                continue
            k, _, v = ln.partition("=")
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k and v and k not in env:
                env[k] = v
    except Exception:
        pass
    return env


def _provider_value(pid, env):
    names, joiner = _PROVIDER_ENV[pid]
    if joiner is None:
        for n in names:
            if env.get(n):
                return env[n]
        return None
    if joiner == "intelx":
        key = env.get("INTELX_KEY") or env.get("INTELX_API_KEY")
        if not key:
            return None
        return f"{env.get('INTELX_HOST') or '2.intelx.io'}:{key}"
    parts = [env.get(n) for n in names]
    return joiner.join(parts) if all(parts) else None


def which_tools():
    """{tool: path} for the enumerators present on this machine."""
    found = {}
    for t in ("subfinder", "amass", "assetfinder", "findomain"):
        p = shutil.which(t)
        if not p:
            for d in _TOOL_DIRS:
                cand = os.path.join(d, t)
                if os.path.isfile(cand) and os.access(cand, os.X_OK):
                    p = cand
                    break
        if p:
            found[t] = p
    return found


def sync_subfinder_providers(config_path=None, env=None, dry_run=False, regenerate=False):
    """Provider-config sync from .env. Two modes:
      - MERGE (default): fill only EMPTY provider entries, keep hand-set keys — for the user's
        ~/.config file (never overwrites what the analyst set).
      - REGENERATE (`regenerate=True`): build the file FROM .env ONLY, so a rotated/removed key
        does not linger — used for the skill-owned config that the enumerator passes with `-pc`.
    Never prints a value. Returns {"path","filled","kept","missing"}."""
    env = env or _load_env()
    path = config_path or os.path.join(
        os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "subfinder", "provider-config.yaml")
    if regenerate:
        out, filled, missing = [], [], []
        for pid in _PROVIDER_ENV:
            val = _provider_value(pid, env)
            if val:
                out.append(f"{pid}:")
                out.append(f"  - {json.dumps(val)}")
                filled.append(pid)
            else:
                missing.append(pid)
        if not dry_run:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write("\n".join(out).rstrip("\n") + "\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        return {"path": path, "filled": sorted(filled), "kept": [], "missing": sorted(missing)}
    lines = []
    if os.path.isfile(path):
        lines = open(path, encoding="utf-8").read().splitlines()
    filled, kept, missing = [], [], []
    seen = set()
    out = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        m = re.match(r"^([a-z0-9]+):\s*(.*)$", ln)
        if not m:
            out.append(ln)
            i += 1
            continue
        pid, rest = m.group(1), m.group(2).strip()
        seen.add(pid)
        # gather a block-style list that follows
        block = []
        j = i + 1
        while j < len(lines) and re.match(r"^\s+-\s*\S", lines[j]):
            block.append(lines[j])
            j += 1
        has_value = bool(block) or (rest not in ("", "[]"))
        if has_value:
            kept.append(pid)
            out.append(ln)
            out.extend(block)
        else:
            val = _provider_value(pid, env) if pid in _PROVIDER_ENV else None
            if val:
                out.append(f"{pid}:")
                out.append(f"  - {json.dumps(val)}")
                filled.append(pid)
            else:
                out.append(ln)
                if pid in _PROVIDER_ENV:
                    missing.append(pid)
        i = j
    # providers the file does not list at all but .env can key
    for pid in _PROVIDER_ENV:
        if pid in seen:
            continue
        val = _provider_value(pid, env)
        if val:
            out.append(f"{pid}:")
            out.append(f"  - {json.dumps(val)}")
            filled.append(pid)
    if filled and not dry_run:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("\n".join(out).rstrip("\n") + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    return {"path": path, "filled": sorted(filled), "kept": sorted(kept), "missing": sorted(missing)}


def _run(cmd, timeout, env=None):
    timeout = _floor(timeout)                   # every enumerator subprocess runs up to the ceiling
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return r.returncode, r.stdout, (r.stderr or "")[-2000:]
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s"
    except Exception as e:  # noqa: BLE001
        return -1, "", str(e)


_HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9_-]{1,63}(?<!-))+\.?$", re.I)


def _clean(name, apex):
    n = (name or "").strip().lower().rstrip(".")
    n = re.sub(r"^\*\.", "", n)
    if not n or not _HOST_RE.match(n) or not (n == apex or n.endswith("." + apex)):
        return None
    return n


# keyless subfinder sources only — used when the case posture forbids spending metered provider
# credit. Every entry here is un-starred in `subfinder -ls` (no key required); starred sources
# (alienvault/certspotter/dnsdumpster/…) are deliberately excluded so no key file is consulted.
_FREE_SOURCES = ("crtsh,hackertarget,rapiddns,anubis,commoncrawl,digitorus,sitedossier,"
                 "waybackarchive,threatcrowd")


def enumerate_apex(apex, tools=None, timeout=None, env=None, extra_env=None, pc_path=None, free_only=False):
    """Union of every installed tool's names for `apex`. Returns {name: set(tools)}.
    `pc_path` is a skill-owned subfinder provider config (never the user's ~/.config file).
    `free_only` restricts subfinder to keyless sources so no metered provider credit is spent."""
    timeout = _floor(timeout)
    apex = apex.strip().lower().rstrip(".")
    tools = tools or which_tools()
    names = {}
    runs = {}
    penv = dict(os.environ)
    if extra_env:
        penv.update(extra_env)
    if "subfinder" in tools:
        cmd = [tools["subfinder"], "-d", apex, "-silent"]
        cmd += (["-sources", _FREE_SOURCES] if free_only else ["-all"])
        if free_only:
            cmd += ["-pc", os.devnull]   # keyless run: never read a provider config (not even the default ~/.config)
        elif pc_path and os.path.isfile(pc_path):
            cmd += ["-pc", pc_path]
        rc, out, err = _run(cmd, timeout, env=penv)
        runs["subfinder"] = {"rc": rc, "names": 0, "stderr": err[-300:] if rc else ""}
        for ln in out.splitlines():
            n = _clean(ln, apex)
            if n:
                names.setdefault(n, set()).add("subfinder")
                runs["subfinder"]["names"] += 1
    if "amass" in tools:
        # amass's own -timeout is MINUTES; both it and the subprocess bound are the floored ceiling —
        # the old `min(timeout, 200)` cap was the one un-floored task call left in the engine.
        rc, out, err = _run([tools["amass"], "enum", "-passive", "-d", apex, "-silent",
                             "-timeout", str(max(1, timeout // 60))], timeout, env=penv)
        runs["amass"] = {"rc": rc, "names": 0, "stderr": err[-300:] if rc else ""}
        for ln in out.splitlines():
            # amass v4 prints "name (FQDN) --> a_record --> ip (IPAddress)"; v3 prints bare names
            tok = ln.split()[0] if ln.split() else ""
            n = _clean(tok, apex)
            if n:
                names.setdefault(n, set()).add("amass")
                runs["amass"]["names"] += 1
    if "assetfinder" in tools:
        rc, out, err = _run([tools["assetfinder"], "--subs-only", apex], timeout, env=penv)
        runs["assetfinder"] = {"rc": rc, "names": 0, "stderr": err[-300:] if rc else ""}
        for ln in out.splitlines():
            n = _clean(ln, apex)
            if n:
                names.setdefault(n, set()).add("assetfinder")
                runs["assetfinder"]["names"] += 1
    if "findomain" in tools:
        rc, out, err = _run([tools["findomain"], "-t", apex, "-q"], timeout, env=penv)
        runs["findomain"] = {"rc": rc, "names": 0, "stderr": err[-300:] if rc else ""}
        for ln in out.splitlines():
            n = _clean(ln, apex)
            if n:
                names.setdefault(n, set()).add("findomain")
                runs["findomain"]["names"] += 1
    names.pop(apex, None)
    return names, runs


def _resolve(name, timeout=4.0):
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(name, None)
        ips = sorted({i[4][0] for i in infos})
        return ips
    except Exception:
        return []


def resolve_many(names, workers=16):
    out = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for n, ips in zip(names, ex.map(_resolve, names)):
            out[n] = ips
    return out


def _skill_provider_config():
    """A skill-owned, gitignored subfinder provider config — so the enumerator never mutates the
    user's ~/.config/subfinder/provider-config.yaml. Kept next to .env at the skill root."""
    return os.path.join(SKILL, ".subfinder-provider-config.yaml")


def sync_providers(free_only=False):
    """Build the subfinder provider config from .env ONCE (skill-owned path, never ~/.config) and
    return the sync record. A caller fanning `run()` across apexes in threads calls this first and
    passes the record as `sync=`, so N threads never rewrite the file other threads' subfinder
    processes are reading."""
    if free_only:
        return {"filled": [], "kept": [], "missing": []}
    return sync_subfinder_providers(config_path=_skill_provider_config(), env=_load_env(), regenerate=True)


def run(apex, case_dir=None, timeout=None, no_resolve=False, free_only=False, sync=None):
    env = _load_env()
    # free-only leaves NO key file behind: skip the sync entirely (enumerate_apex uses -pc /dev/null).
    # Otherwise build a FRESH provider config from .env into a skill-owned path (never touch ~/.config)
    # — unless the caller pre-synced (`sync=` from sync_providers()), in which case reuse it.
    cfg = _skill_provider_config()
    sync = sync if sync is not None else sync_providers(free_only=free_only)
    tools = which_tools()
    res = {"apex": apex.lower(), "collected_at": _now(), "tools": {t: p for t, p in tools.items()},
           "free_only": free_only, "provider_config": None if free_only else cfg,
           "provider_sync": {"filled": sync["filled"], "kept": sync["kept"], "missing": sync["missing"]},
           "subdomains": [], "live": [], "dead": [], "runs": {}}
    if not tools:
        res["error"] = ("no enumerator installed (subfinder / amass / assetfinder / findomain) — "
                        "scripts/install.sh --all installs subfinder")
    else:
        names, runs = enumerate_apex(apex, tools, timeout=timeout, env=env,
                                     pc_path=None if free_only else cfg, free_only=free_only)
        res["runs"] = runs
        ips = {} if no_resolve else resolve_many(sorted(names))
        for n in sorted(names):
            row = {"name": n, "sources": sorted(names[n]), "ips": ips.get(n, []) if not no_resolve else None}
            res["subdomains"].append(row)
            if no_resolve or row["ips"]:
                res["live"].append(n)
            else:
                res["dead"].append(n)
    if case_dir:
        d = os.path.join(case_dir, "subenum")
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, apex.lower() + ".json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=2, ensure_ascii=False)
        res["path"] = p
    return res


def summarize(res):
    L = [f"subenum {res['apex']}: {len(res.get('subdomains') or [])} name(s) from "
         f"{', '.join(res.get('tools') or []) or 'no tool'} — {len(res.get('live') or [])} resolving, "
         f"{len(res.get('dead') or [])} dead"]
    ps = res.get("provider_sync") or {}
    if ps.get("filled"):
        L.append(f"  subfinder providers keyed from .env this run: {', '.join(ps['filled'])}")
    if ps.get("missing"):
        L.append(f"  subfinder providers still unkeyed: {', '.join(ps['missing'])}")
    for t, r in (res.get("runs") or {}).items():
        L.append(f"  {t}: {r['names']} name(s)" + (f"  rc={r['rc']} {r['stderr']}" if r.get("rc") else ""))
    for n in (res.get("live") or [])[:40]:
        row = next((s for s in res["subdomains"] if s["name"] == n), {})
        L.append(f"    {n:<48} {','.join(row.get('sources') or [])}  {' '.join((row.get('ips') or [])[:2])}")
    if res.get("error"):
        L.append("  " + res["error"])
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description="subdomain enumeration via installed passive tools, keyed from .env")
    ap.add_argument("apex", nargs="?", help="registrable domain")
    ap.add_argument("--case-dir", help="persist to <case-dir>/subenum/<apex>.json")
    ap.add_argument("--timeout", type=int, default=240)
    ap.add_argument("--no-resolve", action="store_true")
    ap.add_argument("--sync-only", action="store_true", help="only sync subfinder's provider-config from .env")
    ap.add_argument("--free-only", action="store_true", dest="free_only",
                    help="keyless subfinder sources only (no metered provider credit spent)")
    ap.add_argument("--pretty", action="store_true")
    a = ap.parse_args(argv)
    if a.sync_only or not a.apex:
        s = sync_subfinder_providers()
        print(json.dumps({"path": s["path"], "filled": s["filled"], "kept": s["kept"], "missing": s["missing"],
                          "tools": which_tools()}, indent=2))
        return 0
    res = run(a.apex, case_dir=a.case_dir, timeout=a.timeout, no_resolve=a.no_resolve, free_only=a.free_only)
    print(json.dumps(res, ensure_ascii=False, indent=2 if a.pretty else None))
    print(summarize(res), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
