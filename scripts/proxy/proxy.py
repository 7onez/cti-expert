#!/usr/bin/env python3
"""
proxy.py — cti-expert egress-proxy manager (the `/proxy` command).

cti-expert routes every HTTP(S) request the collectors make (keyless crt.sh,
Wayback/CDX, urlscan, the CLD connector, WHOIS, analytics reverses, `/apikeys
test`) through the
process-global opener installed by `cti_proxy.install()`. This tool is the
single control surface for what that opener uses: add one proxy, add a POOL of
rotation proxies, choose a rotation policy, test them, or print export lines for
a shell / another tool.

Store (chmod-600, gitignored): scripts/proxy/proxies.json
(overridable via CTI_PROXY_STORE). Env always wins over the file:
CTI_PROXIES / CTI_PROXY, CTI_PROXY_ENABLED, CTI_PROXY_ROTATION, NO_PROXY.

Runner (zero setup, any OS): `uv run scripts/proxy/proxy.py [command]`
Stdlib-only — plain `python3`/`py` works too.

Commands:
    proxy.py                       # status (default): pool + policy + toggles
    proxy.py add http://u:p@h:port [--label res-1]
    proxy.py add h:port            # bare host:port -> http:// assumed
    proxy.py remove <url|index>    # drop one entry
    proxy.py clear                 # drop all entries
    proxy.py enable | disable      # master switch for the whole layer
    proxy.py rotation round-robin|random|sticky|off
    proxy.py allow-direct on|off   # fall back to a direct connection as last resort
    proxy.py no-proxy a.com,b.com  # hosts to reach without a proxy (replace list)
    proxy.py test [--url URL] [--timeout N]   # probe each proxy's egress IP
    proxy.py use [--json]          # advance rotation + print the next proxy's exports
    proxy.py example               # print the .env proxy block
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cti_proxy as cp   # shared library (config, rotation, failover, test)


def _mask(url):
    """Hide proxy credentials in output (user:pass@ -> user:***@)."""
    if "@" not in url:
        return url
    creds, host = url.split("://", 1)[-1].split("@", 1)
    scheme = url.split("://", 1)[0] if "://" in url else "http"
    user = creds.split(":", 1)[0]
    return f"{scheme}://{user}:***@{host}"


def _ensure_pysocks():
    """SOCKS proxies need PySocks for urllib. Install it on demand (uv, else pip),
    best-effort — a failure just prints the manual one-liner, never blocks the add."""
    try:
        import socks  # noqa: F401
        return True
    except Exception:
        pass
    import shutil
    import subprocess
    cmd = (["uv", "pip", "install", "pysocks"] if shutil.which("uv")
           else [sys.executable, "-m", "pip", "install", "pysocks"])
    print(f"  socks proxy needs PySocks — installing: {' '.join(cmd)}")
    try:
        if subprocess.run(cmd).returncode == 0:
            return True
    except Exception:
        pass
    print("  could not auto-install PySocks; run it yourself: uv pip install pysocks",
          file=sys.stderr)
    return False


def cmd_status(cfg, args):
    pool = cp.build_pool(cfg)
    entries = cfg.get("proxies") or []
    print("cti-expert proxy layer")
    print(f"  enabled      : {cp.is_enabled(cfg)}")
    print(f"  rotation     : {cp.rotation_mode(cfg)}")
    print(f"  allow_direct : {cp.allow_direct(cfg)}")
    print(f"  no_proxy     : {', '.join(cp.no_proxy_hosts(cfg)) or '(none)'}")
    print(f"  store        : {cp.STORE_PATH}")
    if os.environ.get("CTI_PROXIES") or os.environ.get("CTI_PROXY"):
        print("  note         : env CTI_PROXY/CTI_PROXIES is set and OVERRIDES the file")
    print(f"  stored proxies ({len(entries)}):")
    for i, p in enumerate(entries):
        flag = " " if p.get("enabled", True) else "x"
        last = p.get("last_ok") or "never tested"
        label = f"  [{p['label']}]" if p.get("label") else ""
        print(f"    [{i}]({flag}) {_mask(cp.normalize_proxy(p['url']) or p['url'])}"
              f"{label}   last_ok={last}")
    print(f"  effective egress pool ({len(pool)}): "
          f"{', '.join(_mask(p) for p in pool) or '(direct — no proxy)'}")
    return 0


def cmd_add(cfg, args):
    url = cp.normalize_proxy(args.url)
    if not url:
        print(f"invalid proxy URL: {args.url!r}  "
              f"(use scheme://[user:pass@]host:port; {'/'.join(cp.VALID_SCHEMES)})",
              file=sys.stderr)
        return 2
    for p in cfg["proxies"]:
        if cp.normalize_proxy(p["url"]) == url:
            print(f"already present: {_mask(url)}")
            return 0
    if cp.urlsplit(url).scheme.startswith("socks"):
        _ensure_pysocks()
    cfg["proxies"].append({"url": url, "label": args.label or "",
                           "enabled": True, "added": cp.now_iso(), "last_ok": None})
    cfg["enabled"] = True
    cp.save_store(cfg)
    print(f"added: {_mask(url)}  (pool now {len(cfg['proxies'])})")
    return 0


def cmd_remove(cfg, args):
    entries = cfg["proxies"]
    target = args.ref
    idx = None
    if target.isdigit() and int(target) < len(entries):
        idx = int(target)
    else:
        norm = cp.normalize_proxy(target)
        for i, p in enumerate(entries):
            if cp.normalize_proxy(p["url"]) == norm:
                idx = i
                break
    if idx is None:
        print(f"not found: {target}", file=sys.stderr)
        return 2
    removed = entries.pop(idx)
    cp.save_store(cfg)
    print(f"removed: {_mask(cp.normalize_proxy(removed['url']) or removed['url'])}")
    return 0


def cmd_clear(cfg, args):
    n = len(cfg["proxies"])
    cfg["proxies"] = []
    cp.save_store(cfg)
    print(f"cleared {n} prox{'y' if n == 1 else 'ies'}")
    return 0


def cmd_enable(cfg, args):
    cfg["enabled"] = True
    cp.save_store(cfg)
    print("proxy layer ENABLED")
    return 0


def cmd_disable(cfg, args):
    cfg["enabled"] = False
    cp.save_store(cfg)
    print("proxy layer DISABLED (all requests go direct)")
    return 0


def cmd_rotation(cfg, args):
    if args.mode not in ("round-robin", "random", "sticky", "off"):
        print("mode must be one of: round-robin | random | sticky | off",
              file=sys.stderr)
        return 2
    cfg["rotation"] = args.mode
    cp.save_store(cfg)
    print(f"rotation = {args.mode}")
    return 0


def cmd_allow_direct(cfg, args):
    cfg["allow_direct"] = args.state.lower() in cp._TRUE
    cp.save_store(cfg)
    print(f"allow_direct = {cfg['allow_direct']}")
    return 0


def cmd_no_proxy(cfg, args):
    cfg["no_proxy"] = [h.strip() for h in args.hosts.split(",") if h.strip()]
    cp.save_store(cfg)
    print(f"no_proxy = {', '.join(cfg['no_proxy']) or '(none)'}")
    return 0


def cmd_test(cfg, args):
    pool = cp.build_pool(cfg)
    if not pool:
        print("no proxies configured — nothing to test")
        return 1
    rc = 0
    file_urls = {cp.normalize_proxy(p["url"]): p for p in cfg["proxies"]}
    for p in pool:
        ok, detail = cp.test_proxy(p, args.url, args.timeout)
        print(f"  {'OK ' if ok else 'ERR'} {_mask(p)} -> {detail}")
        if ok and p in file_urls:
            file_urls[p]["last_ok"] = cp.now_iso()
        rc = rc or (0 if ok else 2)
    cp.save_store(cfg)
    return rc


def cmd_use(cfg, args):
    pool = cp.build_pool(cfg)
    if not pool or not cp.is_enabled(cfg):
        # emit unsets so `eval` cleanly disables a previous export
        if args.json:
            print(json.dumps({"proxy": None}))
        else:
            print("unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy")
        return 0
    chosen = pool[cp.pick_start(pool, cp.rotation_mode(cfg))]
    if args.json:
        print(json.dumps({"proxy": chosen}))
        return 0
    npx = ",".join(cp.no_proxy_hosts(cfg))
    print(f"export HTTP_PROXY={chosen} HTTPS_PROXY={chosen} ALL_PROXY={chosen}")
    print(f"export http_proxy={chosen} https_proxy={chosen} all_proxy={chosen}")
    if npx:
        print(f"export NO_PROXY={npx} no_proxy={npx}")
    return 0


def cmd_example(cfg, args):
    print("""# --- Egress proxy / rotation (managed by `/proxy`) ---------------
# Leave blank to run with your real IP. Env here OVERRIDES proxies.json.
# Single proxy (scheme://[user:pass@]host:port; http/https/socks5/socks5h):
CTI_PROXY=
# Rotation POOL — comma/space/newline separated; enables round-robin failover:
CTI_PROXIES=
# Master switch (1/0). Blank -> on when a pool exists.
CTI_PROXY_ENABLED=
# round-robin | random | sticky | off
CTI_PROXY_ROTATION=
# Fall back to a DIRECT connection if every proxy fails (1/0). Default 0.
CTI_PROXY_ALLOW_DIRECT=
# Hosts reached without a proxy:
NO_PROXY=localhost,127.0.0.1""")
    return 0


def build_parser():
    ap = argparse.ArgumentParser(prog="proxy.py", add_help=True,
                                 description="cti-expert egress-proxy manager")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("status")
    a = sub.add_parser("add"); a.add_argument("url"); a.add_argument("--label", default="")
    r = sub.add_parser("remove"); r.add_argument("ref")
    sub.add_parser("clear")
    sub.add_parser("enable")
    sub.add_parser("disable")
    ro = sub.add_parser("rotation"); ro.add_argument("mode")
    ad = sub.add_parser("allow-direct"); ad.add_argument("state")
    npx = sub.add_parser("no-proxy"); npx.add_argument("hosts")
    t = sub.add_parser("test"); t.add_argument("--url", default=None); t.add_argument("--timeout", type=int, default=15)
    u = sub.add_parser("use"); u.add_argument("--json", action="store_true")
    e = sub.add_parser("env"); e.add_argument("--json", action="store_true")   # alias of use
    sub.add_parser("example")
    return ap


def main(argv):
    ap = build_parser()
    args = ap.parse_args(argv)
    cfg = cp.load_store()
    dispatch = {
        None: cmd_status, "status": cmd_status, "add": cmd_add, "remove": cmd_remove,
        "clear": cmd_clear, "enable": cmd_enable, "disable": cmd_disable,
        "rotation": cmd_rotation, "allow-direct": cmd_allow_direct,
        "no-proxy": cmd_no_proxy, "test": cmd_test, "use": cmd_use, "env": cmd_use,
        "example": cmd_example,
    }
    return dispatch[args.cmd](cfg, args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
