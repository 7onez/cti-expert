#!/usr/bin/env python3
"""
apikeys.py — cti-expert premium/pro API-key manager (the `/apikeys` command).

cti-expert runs keyless/free by default. Premium keys are STRICTLY ADDITIVE:
they upgrade existing techniques (higher limits, reverse-lookup endpoints) and
never gate the keyless path. This tool is the single control surface for them.

Key store (chmod-600, gitignored): the skill-root `.env`
(`~/.claude/skills/cti-expert/.env`), overridable via `CTI_API_KEYS_ENV`.
Resolution everywhere is ENV VAR first, then this `.env`. Values are always
masked in output — the plaintext key is never printed.

Recommended runner (zero setup, any OS): `uv run apikeys.py [command]`
Stdlib-only — no dependencies, so plain `python3`/`py` works too.

Commands:
    uv run apikeys.py                     # status (default): what's set + unlocked
    uv run apikeys.py status --all        # include services with no key set
    uv run apikeys.py set shodan KEY      # store a key (or: set SHODAN_API_KEY KEY)
    uv run apikeys.py set shodan          # read the value from stdin (not echoed on CLI)
    uv run apikeys.py unset shodan        # remove a key from the .env
    uv run apikeys.py test [shodan]       # live-probe one/all keys that have a test
    uv run apikeys.py unlocks             # which cti-expert commands your keys upgrade
    uv run apikeys.py path                # print the .env path + status
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
import sys
import os
import json
import argparse
import urllib.request
import urllib.error

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

# --- egress proxy / rotation: route outbound HTTP through the /proxy pool ----
def _install_cti_proxy():
    import os as _o, sys as _s
    _b = _o.path.dirname(_o.path.abspath(__file__))
    for _ in range(6):
        _c = _o.path.join(_b, "proxy", "cti_proxy.py")
        if _o.path.isfile(_c):
            _s.path.insert(0, _o.path.dirname(_c))
            try:
                import cti_proxy
                cti_proxy.install()
            except Exception:
                pass
            return
        _p = _o.path.dirname(_b)
        if _p == _b:
            return
        _b = _p
_install_cti_proxy()

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(HERE, "registry.json")
# skill root = ../../ from scripts/apikeys/ ; same target the webpivot tools resolve.
ENV_PATH = os.environ.get("CTI_API_KEYS_ENV") or os.path.normpath(
    os.path.join(HERE, "..", "..", ".env"))
UA = "cti-expert-apikeys/1.0"


# ───────────────────────────────────────────────────────────── registry + store
def load_registry():
    with open(REGISTRY, "r", encoding="utf-8") as f:
        return json.load(f)["services"]


def load_env_file(path=ENV_PATH):
    """Parse KEY=VALUE lines from the .env into a dict (comments/blanks ignored)."""
    out = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return out


def resolve(var, file_env):
    """Return (value, source): env var wins, then the .env file, else (None,None)."""
    v = os.environ.get(var)
    if v and v.strip():
        return v.strip(), "env"
    v = file_env.get(var)
    if v and v.strip():
        return v.strip(), "file"
    return None, None


def mask(v):
    v = (v or "").strip()
    if not v:
        return "—"
    if len(v) <= 6:
        return "•" * len(v) + f" ({len(v)})"
    return "…" + v[-2:] + f" ({len(v)} chars)"


def all_vars(svc):
    """Primary env var + aliases + extra (secondary) vars for a service."""
    return ([svc["env"]] + svc.get("aliases", []) + svc.get("extra", []))


def find_service(services, token):
    """Match a service by id, primary env var, alias, or extra var (case-insensitive)."""
    t = token.strip().lower()
    for s in services:
        if s["id"].lower() == t or s["env"].lower() == t:
            return s, s["env"]
        for a in s.get("aliases", []) + s.get("extra", []):
            if a.lower() == t:
                return s, a
    return None, None


# ─────────────────────────────────────────────────────────────────── .env write
def write_env(var, value, path=ENV_PATH):
    """Set var=value in the .env (update in place or append). Creates chmod-600."""
    lines = []
    found = False
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    for i, ln in enumerate(lines):
        if ln.strip().startswith(f"{var}=") or ln.strip().startswith(f"{var} ="):
            lines[i] = f"{var}={value}"
            found = True
            break
    if not found:
        if not lines or (lines and lines[-1].strip()):
            pass
        lines.append(f"{var}={value}")
    header = "# cti-expert API keys — chmod 600, gitignored. Managed by /apikeys. Never commit."
    if not lines or not lines[0].startswith("# cti-expert API keys"):
        lines = [header] + lines
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    _chmod_600(path)


def remove_env(var, path=ENV_PATH):
    if not os.path.exists(path):
        return False
    with open(path, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()
    new = [ln for ln in lines
           if not (ln.strip().startswith(f"{var}=") or ln.strip().startswith(f"{var} ="))]
    changed = len(new) != len(lines)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(new) + ("\n" if new else ""))
    _chmod_600(path)
    return changed


def _chmod_600(path):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows perms differ; .gitignore is the real safeguard


# ─────────────────────────────────────────────────────────────────────── probe
def probe(svc, key):
    """Live-validate a key using the registry test spec. Returns (state, detail).
    state ∈ {'valid','invalid','error','no-test'}."""
    spec = svc.get("test")
    if not spec:
        return "no-test", "no automated probe — run a real query to confirm"
    url = spec["url"].replace("{key}", key)
    headers = {"User-Agent": UA}
    for hk, hv in (spec.get("header") or {}).items():
        headers[hk] = hv.replace("{key}", key)
    if spec.get("bearer"):
        headers["Authorization"] = f"Bearer {key}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as r:
            status = r.getcode()
            body = r.read(20000)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return "invalid", f"HTTP {e.code} (unauthorized — key rejected)"
        return "error", f"HTTP {e.code}"
    except Exception as e:  # noqa
        return "error", str(e)
    if "expect_json" in spec:
        try:
            data = json.loads(body.decode("utf-8", "replace"))
            if spec["expect_json"] in (data or {}):
                return "valid", f"HTTP {status}, has '{spec['expect_json']}'"
            return "invalid", f"HTTP {status} but '{spec['expect_json']}' absent"
        except Exception:  # noqa
            return "error", f"HTTP {status}, unparseable JSON"
    if status == spec.get("expect_status", 200):
        return "valid", f"HTTP {status}"
    return "invalid", f"HTTP {status}"


# ───────────────────────────────────────────────────────────────────── commands
CAT_ORDER = ["infra", "dns", "analytics", "breach", "crypto", "code", "dork", "ai"]
CAT_LABEL = {"infra": "Infrastructure / host search", "dns": "DNS / certs / WHOIS",
             "analytics": "Analytics-ID pivot", "breach": "Breach / leak / darknet",
             "crypto": "Crypto / blockchain", "code": "Code / repos",
             "dork": "Search-engine dorking", "ai": "AI / vision"}


def cmd_status(services, file_env, show_all):
    present = 0
    active = []
    print(f"cti-expert API keys  ·  store: {ENV_PATH}"
          + ("  (exists)" if os.path.exists(ENV_PATH) else "  (not created yet)"))
    print("keyless/free mode always works — the keys below are additive upgrades.\n")
    for cat in CAT_ORDER:
        rows = []
        for s in services:
            if s.get("category") != cat:
                continue
            val, src = resolve(s["env"], file_env)
            for a in s.get("aliases", []):
                if not val:
                    val, src = resolve(a, file_env)
            if val:
                present += 1
                active.append(s["id"])
            elif not show_all:
                continue
            mark = "✅" if val else "  "
            state = f"{mask(val)} [{src}]" if val else "not set"
            rows.append((mark, s["id"], s["env"], state, s["tier"], s["unlocks"]))
        if rows:
            print(f"▸ {CAT_LABEL[cat]}")
            for mark, sid, env, state, tier, unlocks in rows:
                print(f"  {mark} {sid:<15} {env:<26} {state}")
                print(f"       {tier:<10} {unlocks}")
            print()
    print(f"{present} key(s) configured"
          + (f"  ·  premium active: {', '.join(active)}" if active else "")
          + (f"\nAll {len(services)} services shown." if show_all
             else "\nRun with --all to see every supported service and how to get a key."))


def cmd_set(services, args):
    svc, var = find_service(services, args.service)
    if not svc:
        # allow storing an arbitrary VAR the user names explicitly (e.g. *_FALLBACK)
        var = args.service if args.service.isupper() or "_" in args.service else None
        if not var:
            print(f"Unknown service '{args.service}'. Run `apikeys.py status --all` "
                  f"to list ids, or pass an explicit ENV_VAR name.", file=sys.stderr)
            return 2
    value = args.value
    if value is None:
        value = sys.stdin.readline().strip()
    if not value:
        print("No value provided (empty). Nothing written.", file=sys.stderr)
        return 2
    write_env(var, value, ENV_PATH)
    label = svc["name"] if svc else var
    print(f"✅ stored {var} for {label} → {ENV_PATH} (chmod 600). Value masked: {mask(value)}")
    if svc:
        print(f"   unlocks: {svc['unlocks']}")
    if os.environ.get(var):
        print(f"   note: env var {var} is also set and OVERRIDES the .env at runtime.")
    return 0


def cmd_unset(services, args):
    svc, var = find_service(services, args.service)
    var = var or args.service
    if remove_env(var, ENV_PATH):
        print(f"🗑️  removed {var} from {ENV_PATH}")
    else:
        print(f"{var} was not present in {ENV_PATH}")
    return 0


def cmd_test(services, file_env, args):
    targets = services
    if args.service:
        svc, _ = find_service(services, args.service)
        if not svc:
            print(f"Unknown service '{args.service}'.", file=sys.stderr)
            return 2
        targets = [svc]
    icons = {"valid": "🟢", "invalid": "🔴", "error": "🟠", "no-test": "⚪"}
    any_tested = False
    for s in targets:
        val, src = resolve(s["env"], file_env)
        if not val:
            if args.service:
                print(f"⚪ {s['id']}: no key set")
            continue
        state, detail = probe(s, val)
        any_tested = True
        print(f"{icons[state]} {s['id']:<15} {state:<8} {detail}   [{src}]")
    if not any_tested and not args.service:
        print("No keys with an automated probe are set. Use `set` first, or `status`.")
    return 0


def cmd_unlocks(services, file_env):
    active = [s for s in services if resolve(s["env"], file_env)[0]]
    if not active:
        print("No premium keys configured — cti-expert is running in keyless/free mode.\n"
              "Add keys with `apikeys.py set <service> <key>`; see `status --all`.")
        return 0
    print("Premium capabilities currently unlocked:\n")
    for s in active:
        print(f"  ✅ {s['name']}\n     {s['unlocks']}")
    return 0


def cmd_path():
    exists = os.path.exists(ENV_PATH)
    print(ENV_PATH)
    print(f"exists: {exists}" + ("" if exists else "  (created on first `set`)"))
    if exists:
        try:
            mode = oct(os.stat(ENV_PATH).st_mode & 0o777)
            print(f"perms: {mode} (target 0o600; .gitignore is the primary safeguard)")
        except OSError:
            pass
    print("override with env var CTI_API_KEYS_ENV")
    return 0


def cmd_example(services):
    """Print a fully-commented .env.example template (all keys blank) from the registry."""
    out = [
        "# ============================================================================",
        "#  cti-expert — API keys  (.env.example)",
        "# ============================================================================",
        "#  cti-expert runs KEYLESS / FREE by default. EVERY key below is OPTIONAL and",
        "#  only *upgrades* an existing capability — leave any blank and that feature",
        "#  falls back to its free/keyless path.",
        "#",
        "#  HOW TO USE",
        '#    1) Copy this file to ".env" in this same folder (the skill root):',
        "#         cp .env.example .env",
        "#    2) Paste in the keys you have; leave the rest blank.",
        "#    -- or, instead of editing the file --",
        "#         uv run scripts/apikeys/apikeys.py set shodan <YOUR_KEY>",
        "#",
        "#  Resolution order:  environment variable  >  this .env  >  keyless",
        '#  Security:  never commit your real ".env" (it is gitignored); chmod 600.',
        "#  Check:     uv run scripts/apikeys/apikeys.py status | test | unlocks",
        "#  Regenerate:  uv run scripts/apikeys/apikeys.py example > .env.example",
        "# ============================================================================",
    ]
    for cat in CAT_ORDER:
        svcs = [s for s in services if s.get("category") == cat]
        if not svcs:
            continue
        label = CAT_LABEL[cat]
        out.append("")
        out.append(f"# --- {label} " + "-" * max(3, 60 - len(label)))
        for s in svcs:
            out.append(f"# {s['name']} — {s['unlocks']}  ({s['tier']})")
            out.append(f"#   get a key: {s['url']}")
            out.append(f"{s['env']}=")
            for extra in s.get("extra", []):
                out.append(f"{extra}=")
    # --- Non-key config (not a premium service; survives regeneration) ----------
    out.append("")
    out.append("# --- Optional: persistent intelligence backend " + "-" * 15)
    out.append("# Path to the intel_engine engine (persistent KB + cross-case correlation).")
    out.append("# Optional — leave blank to run stateless. When set, unlocks /backend /kb /recall /binary.")
    out.append("# Auto-resolved if blank: .mcp.json > sibling intel_engine/ dir > ~/.claude symlink.")
    out.append("# See connectors/intel-backend.md")
    out.append("INTEL_HOME=")
    print("\n".join(out))
    return 0


def main():
    ap = argparse.ArgumentParser(description="cti-expert premium API-key manager (/apikeys)")
    sub = ap.add_subparsers(dest="cmd")
    ps = sub.add_parser("status", help="show configured keys + what they unlock")
    ps.add_argument("--all", action="store_true", help="include services with no key set")
    pset = sub.add_parser("set", help="store a key in the skill .env")
    pset.add_argument("service"); pset.add_argument("value", nargs="?")
    punset = sub.add_parser("unset", help="remove a key from the .env")
    punset.add_argument("service")
    pt = sub.add_parser("test", help="live-probe key validity")
    pt.add_argument("service", nargs="?")
    sub.add_parser("unlocks", help="list capabilities your current keys unlock")
    sub.add_parser("path", help="print the .env path + status")
    sub.add_parser("example", help="print a blank, commented .env.example template")
    args = ap.parse_args()

    services = load_registry()
    file_env = load_env_file()

    if args.cmd in (None, "status"):
        return cmd_status(services, file_env, getattr(args, "all", False))
    if args.cmd == "set":
        return cmd_set(services, args)
    if args.cmd == "unset":
        return cmd_unset(services, args)
    if args.cmd == "test":
        return cmd_test(services, file_env, args)
    if args.cmd == "unlocks":
        return cmd_unlocks(services, file_env)
    if args.cmd == "path":
        return cmd_path()
    if args.cmd == "example":
        return cmd_example(services)
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
