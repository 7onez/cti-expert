#!/usr/bin/env python3
"""deep_profile.py — the /email-deep and /breach-deep chains, as a COMPOSITION.

These two commands promised "accounts, breach history, infrastructure" and "multi-source breach
lookup with context". Every piece already exists as a tool: email_hygiene grades the domain,
email_permute generates candidates, intelx_search hits the leak corpora, reputation_check covers
domain reputation, subdomain_enum and msft_recon cover the infrastructure side.

So this ORCHESTRATES rather than collects. Writing new collectors here would duplicate five tools
and guarantee they drift — the exact failure this branch has spent its time undoing.

It runs the local, keyless steps itself, and it sends a keyed lookup when the selector
needs that lookup and the key is set. An email needs Hudson Rock, ZoneCruncher, an IntelX
search, and a reverse-WHOIS of that address. A domain needs the first three, not a
reverse-WHOIS. WhoisXML history is not this question. HIBP runs only when HIBP_API_KEY
is set. `--free-only` sends none of the metered calls.

Usage:
  deep_profile.py user@example.com
  deep_profile.py user@example.com --mode breach --pretty
  deep_profile.py user@example.com --free-only
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
sys.path.insert(0, HERE)
import keyed_feeds  # noqa: E402 — sends HUDSONROCK_API_KEY / ZONECRUNCHER_API_KEY
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
SKILL = os.path.normpath(os.path.join(HERE, "..", ".."))
WP = os.path.join(SKILL, "intel_engine", "WebPivot", "tools")
DISPATCHER = os.path.join(SKILL, "scripts", "backend", "intel.py")
BULK_REVERSE = 150


def no_spend(flag=False):
    v = (os.environ.get("CTI_FREE_ONLY") or "").strip().lower()
    return bool(flag) or v in ("1", "true", "yes")


def _shrink_intelx(result):
    """Keep the count and the skip reason. Do not keep leak rows in this profile."""
    if not isinstance(result, dict):
        return {"status": "ok", "note": "unparsed"}
    recs = result.get("records") or []
    return {"status": "ok" if not result.get("skipped") else "skipped",
            "selector": result.get("selector"), "term": result.get("term"),
            "records": len(recs) if isinstance(recs, list) else 0,
            "logs_pass": result.get("logs_pass"),
            "skipped": result.get("skipped"),
            "ui_url": result.get("ui_url")}


def send_intelx(sel):
    """One logs-only search. The dispatcher cwd is the engine, so the case memo applies."""
    got = run(os.path.dirname(DISPATCHER), "intel.py", "intelx", "search", sel, "--logs-only",
              timeout=120)
    if got.get("status") != "ok":
        return got
    inner = got.get("result")
    if isinstance(inner, dict):
        return _shrink_intelx(inner)
    return {"status": "ok", "raw": (got.get("raw") or "")[:300]}


def send_reverse_whois(email):
    """Preview first. Purchase only a small count. Never a KB edge from this profile."""
    preview = run(os.path.dirname(DISPATCHER), "intel.py", "reverse-whois",
                  "--reverse-email", email, "--reverse-mode", "preview", "--json", timeout=60)
    inner = (preview.get("result") or {}).get("reverse_email") if preview.get("status") == "ok" else None
    if not isinstance(inner, dict):
        return preview if preview.get("status") != "ok" else {"status": "unavailable", "stage": "preview"}
    if inner.get("error"):
        return {"status": "unavailable", "stage": "preview", "error": str(inner.get("error"))[:300]}
    count = inner.get("count")
    if not isinstance(count, int):
        return {"status": "unavailable", "stage": "preview", "note": "no count — not purchased"}
    if count == 0:
        return {"status": "ok", "stage": "preview", "count": 0, "purchased": False}
    if count > BULK_REVERSE:
        return {"status": "skipped", "stage": "preview", "count": count, "purchased": False,
                "note": f"count {count} exceeds {BULK_REVERSE} — shared boilerplate, not purchased"}
    bought = run(os.path.dirname(DISPATCHER), "intel.py", "reverse-whois",
                 "--reverse-email", email, "--reverse-mode", "purchase", "--json", timeout=90)
    domains = ((bought.get("result") or {}).get("reverse_email") or {}).get("domains") or []
    return {"status": "ok" if bought.get("status") == "ok" else bought.get("status"),
            "stage": "purchase", "count": count, "purchased": True,
            "domains": [d for d in domains if isinstance(d, str)][:50]}



def main():
    ap = argparse.ArgumentParser(description="Compose the email-deep / breach-deep chain.")
    ap.add_argument("selector", help="an email address (or a domain for the infra half)")
    ap.add_argument("--mode", choices=["email", "breach"], default="email")
    ap.add_argument("--free-only", action="store_true",
                    help="do not send metered keys (Hudson Rock, ZoneCruncher, IntelX, reverse-WHOIS)")
    ap.add_argument("--case", help="case dir; sets WP_CASE_DIR so IntelX and reverse-WHOIS dedup")
    ap.add_argument("-o", "--out", help="also write the JSON profile here")
    ap.add_argument("--pretty", action="store_true")
    a = ap.parse_args()

    keyed_feeds.load_keys()
    if no_spend(a.free_only):
        os.environ["CTI_FREE_ONLY"] = "1"
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

    # Hudson Rock and ZoneCruncher send when keyed. IntelX and reverse-WHOIS send
    # through the dispatcher so the case memo applies. HIBP stays planned.
    if a.case:
        os.environ["WP_CASE_DIR"] = a.case
        # every keyed leg (Hudson Rock, ZoneCruncher, IntelX, reverse-WHOIS) ledgers under the case
        os.environ.setdefault("INTEL_CASE", os.path.basename(os.path.normpath(a.case)))
    q = sel if m else domain
    hold = no_spend(a.free_only)
    intelx_ok = bool(m or ("." in q and " " not in q))
    keyed = [
        ("hudsonrock", f"python3 scripts/osint/keyed_feeds.py hudsonrock '{sel}'",
         "Cavalier v3 — HUDSONROCK_API_KEY as the api-key header",
         bool(os.environ.get("HUDSONROCK_API_KEY"))),
        ("zonecruncher", f"python3 scripts/osint/keyed_feeds.py zonecruncher '{q}'",
         "ZoneCruncher v2 — ZONECRUNCHER_API_KEY as the token query param",
         bool(os.environ.get("ZONECRUNCHER_API_KEY"))),
        ("intelx_search", f"python3 intel_engine/WebPivot/tools/wp_intelx.py search '{sel}' --logs-only",
         "one stealer-log search of this email or domain — not a phonebook",
         bool(intelx_ok and (os.environ.get("INTELX_API_KEY") or os.environ.get("INTELX_KEY")))),
        ("reverse_whois", f"python3 intel_engine/WebPivot/tools/whois_enrich.py --reverse-email '{sel}'",
         "WhoisXML reverse-WHOIS of this email. Preview first; purchase only if count <= 150. Not WHOIS history",
         bool(m and os.environ.get("WHOISXML_API_KEY"))),
        ("hibp", "HaveIBeenPwned API", "breach membership — needs HIBP_API_KEY, which is not set",
         bool(os.environ.get("HIBP_API_KEY"))),
    ]
    sendable = {
        "hudsonrock": lambda: keyed_feeds.hudsonrock_lookup(sel),
        "zonecruncher": lambda: keyed_feeds.zonecruncher_lookup(q),
        "intelx_search": lambda: send_intelx(sel),
        "reverse_whois": lambda: send_reverse_whois(sel),
    }
    for name, cmd, why, have in keyed:
        if hold and name in sendable:
            status = "HELD — --free-only"
        elif name in sendable and have:
            out["ran"][name] = sendable[name]()
            status = "RAN — key set and this selector needs it"
        elif have:
            status = "READY — not run"
        else:
            status = "BLOCKED — key absent" if name != "reverse_whois" or m else "n/a — not an email"
            if name == "reverse_whois" and not m:
                status = "n/a — reverse-WHOIS needs an email, not a domain"
            elif name == "intelx_search" and not intelx_ok:
                status = "n/a — not a strong selector"
            elif not have:
                status = "BLOCKED — key absent"
        out["planned"].append({"step": name, "command": cmd, "why": why,
                               "key_present": have, "status": status})

    ran_ok = [k for k, v in out["ran"].items() if str(v.get("status")) in ("ok", "skipped")]
    blocked = [p["step"] for p in out["planned"] if p["status"].startswith("BLOCKED")]
    held = [p["step"] for p in out["planned"] if p["status"].startswith("HELD") or p["status"].startswith("READY")]
    out["verdict"] = (f"{len(ran_ok)} step(s) ran; {len(held)} held")
    if blocked:
        out["collection_gap"] = (f"no key for: {', '.join(blocked)} — that half is UNCOLLECTED. "
                                 f"Absence of a record here means 'not queried', never 'not breached'.")
    out["composition_note"] = ("Keyed lookups run when the selector needs them and the key is set. "
                               "Pass --case so a second email-deep hits the case memo instead of buying "
                               "the same IntelX search again. Reverse-WHOIS is email-only, preview first, "
                               "and is not purchased when the count is bulk. Do not ingest those domains "
                               "as operator edges from this profile. WhoisXML history is never bought here. "
                               "Do not run a second IntelX search on a selector this command already searched.")
    print(f"{sel}: {len(ran_ok)} step(s) ran, {len(held)} held", file=sys.stderr)
    if blocked:
        print(f"  ⚠ collection gap — no key for: {', '.join(blocked)}", file=sys.stderr)
    txt = json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)
    print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
