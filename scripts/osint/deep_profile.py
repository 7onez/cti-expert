#!/usr/bin/env python3
"""deep_profile.py — the /email-deep and /breach-deep chains, as a COMPOSITION.

These two commands promised "accounts, breach history, infrastructure" and "multi-source breach
lookup with context". Every piece already exists as a tool: email_hygiene grades the domain,
email_permute generates candidates, intelx_search hits the leak corpora, reputation_check covers
domain reputation, subdomain_enum and msft_recon cover the infrastructure side.

So this ORCHESTRATES rather than collects. Writing new collectors here would duplicate five tools
and guarantee they drift — the exact failure this branch has spent its time undoing.

It runs the local, keyless steps itself and emits the metered/keyed steps as an explicit plan,
because those spend credits and that is the analyst's call, not a side effect of asking for a
profile.

Usage:
  deep_profile.py user@example.com
  deep_profile.py user@example.com --mode breach --pretty
"""
# /// script
# requires-python = ">=3.9"
# ///
import argparse
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WEBPIVOT = os.path.join(os.path.dirname(HERE), "webpivot")
EMAIL_RE = re.compile(r"^[^@\s]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})$")


def run(script_dir, name, *args, timeout=90):
    path = os.path.join(script_dir, name)
    if not os.path.isfile(path):
        return {"status": f"tool missing: {name}"}
    try:
        r = subprocess.run([sys.executable, path, *args], capture_output=True, text=True,
                           timeout=timeout)
    except Exception as e:  # noqa: BLE001
        return {"status": f"failed ({type(e).__name__})"}
    if r.returncode != 0:
        return {"status": f"exit {r.returncode}", "stderr": (r.stderr or "")[-400:]}
    try:
        return {"status": "ok", "result": json.loads(r.stdout)}
    except Exception:  # noqa: BLE001
        return {"status": "ok", "raw": (r.stdout or "")[:2000]}


def main():
    ap = argparse.ArgumentParser(description="Compose the email-deep / breach-deep chain.")
    ap.add_argument("selector", help="an email address (or a domain for the infra half)")
    ap.add_argument("--mode", choices=["email", "breach"], default="email")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    sel = a.selector.strip()
    m = EMAIL_RE.match(sel)
    domain = m.group(1).lower() if m else sel.lower().split("/")[0]
    out = {"selector": sel, "mode": a.mode, "domain": domain, "ran": {}, "planned": []}

    # --- steps that are free, local and keyless: actually run them -----------------------
    if m:
        out["ran"]["email_hygiene"] = run(WEBPIVOT, "email_hygiene.py", sel)
    out["ran"]["domain_reputation"] = run(HERE, "reputation_check.py", domain)
    out["ran"]["m365_tenant"] = run(HERE, "msft_recon.py", domain)
    if a.mode == "email":
        out["ran"]["subdomains"] = run(HERE, "subdomain_enum.py", domain, timeout=120)

    # --- steps that spend credits or need a key: PLAN them, do not fire them -------------
    keyed = [
        ("intelx_search", f"intel.py intelx '{sel}'",
         "leak / paste / darknet corpora — INTELX_KEY; spends credits", bool(os.environ.get("INTELX_KEY"))),
        ("reverse_whois", f"intel.py reverse-whois --email '{sel}'",
         "domains registered with this address — WhoisXML DRS balance", bool(os.environ.get("WHOISXML_API_KEY"))),
        ("email_permute", f"intel.py email-permute '{sel}'",
         "generate candidate addresses — free, but produces HYPOTHESES only", True),
        ("hibp", "HaveIBeenPwned API", "breach membership — needs HIBP_API_KEY (paid)",
         bool(os.environ.get("HIBP_API_KEY"))),
    ]
    for name, cmd, why, have in keyed:
        out["planned"].append({"step": name, "command": cmd, "why": why,
                               "key_present": have,
                               "status": "READY — not run (spends credits / is a separate decision)"
                                         if have else "BLOCKED — key absent"})

    ran_ok = [k for k, v in out["ran"].items() if v.get("status") == "ok"]
    blocked = [p["step"] for p in out["planned"] if not p["key_present"]]
    out["verdict"] = (f"{len(ran_ok)} free step(s) ran; {len(out['planned'])} metered step(s) "
                      f"planned but NOT executed")
    if blocked:
        out["collection_gap"] = (f"no key for: {', '.join(blocked)} — the breach half of this "
                                 f"profile is UNCOLLECTED. Absence of a breach record here means "
                                 f"'not queried', never 'not breached'.")
    out["composition_note"] = ("This tool orchestrates existing tools; it collects nothing "
                               "itself. Each result above carries its own caveats — read them "
                               "rather than the summary.")
    print(f"{sel}: {len(ran_ok)} free step(s) ran, {len(out['planned'])} metered step(s) planned",
          file=sys.stderr)
    if blocked:
        print(f"  ⚠ collection gap — no key for: {', '.join(blocked)}", file=sys.stderr)
    txt = json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)
    print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
