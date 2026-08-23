#!/usr/bin/env python3
"""
en_report.py — turn a case's ENGAGEMENT artifacts into a citable markdown section for the report.

The engagement (detection → account → panel harvest) leaves a trail under `cases/<case>/engage/`:
`payment_methods.json`, `cluster_expansion.json`, `detect_*.json`, `interactions.jsonl`, the
captured screenshots/DOM and `api_log.json`. This tool reads whatever is present and renders a
"Panel Engagement — Evidence" section: the method/authorization note, the auth surface, the
payment methods (bank + crypto, with base-rate exclusions kept visible), the cluster expansion,
and an EVIDENCE TABLE that cites each fact to the API endpoint or screenshot it came from with the
observation time. Drop the section into the case's `assessment.md` and re-render with IntelReport.

RULE 1: this is tracked, portable code — it holds NO case data. Everything it prints is read at
run time from the git-ignored case folder; nothing is hardcoded here.
"""
from __future__ import annotations

import argparse
import json
import os
import sys


def _load(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _load_jsonl(path):
    rows = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    except Exception:
        pass
    return rows


def _engage_dir(case: str) -> str:
    root = os.environ.get("INTEL_ROOT") or os.getcwd()
    return os.path.join(root, "cases", case, "engage")


def build(case: str) -> str:
    d = _engage_dir(case)
    if not os.path.isdir(d):
        return f"_No engagement artifacts found under cases/{case}/engage/._"
    pm = _load(os.path.join(d, "payment_methods.json")) or {}
    cx = _load(os.path.join(d, "cluster_expansion.json")) or {}
    log = _load_jsonl(os.path.join(d, "interactions.jsonl"))
    det_reg = _load(os.path.join(d, "detect_register.json")) or {}
    det_log = _load(os.path.join(d, "detect_login.json")) or {}

    L = ["# Panel Engagement — Controlled Account and Evidence", ""]
    L.append("Evidence in this section was obtained by **authorised controlled engagement**: a "
             "research account was registered on the operator's own panel — using no real "
             "identity — and used to read the authenticated members area. All findings below are "
             "the operator's own configuration, read from the panel's public and authenticated "
             "responses.")
    L.append("")

    # --- auth surface --------------------------------------------------------------------------
    reg = (det_reg.get("engagement_plan") or {})
    if reg or det_log:
        L += ["## Authentication surface", ""]
        req = ", ".join(f"`{f.get('name')}`" for f in (reg.get("required_fields") or [])) or "—"
        blockers = ", ".join(reg.get("blockers") or []) or "none (no CAPTCHA, no OTP, no email)"
        L.append(f"- **Registration fields:** {req}")
        L.append(f"- **Blockers:** {blockers}")
        L.append(f"- **Registerable without KYC:** {'yes' if reg.get('registerable') else 'no'}")
        L.append("")

    # --- payment methods -----------------------------------------------------------------------
    methods = (pm.get("methods") or {})
    if methods:
        L += ["## Payment methods (how the operator collects)", ""]
        bank = methods.get("vn_bank") or {}
        if bank:
            L.append("**VN bank transfer** (auto-credit):")
            L.append("")
            L.append("| Field | Value |")
            L.append("|---|---|")
            for label, key in (("Bank", "bank"), ("Bank BIN", "bankBin"),
                               ("Account number", "account_number"), ("Account name", "account_name"),
                               ("Minimum", "min_usd"), ("Rate (VND/USD)", "rate_vnd_per_usd")):
                if bank.get(key) not in (None, ""):
                    L.append(f"| {label} | `{bank[key]}` |")
            memo = bank.get("description_memo_prefixes")
            if memo:
                L.append(f"| Transfer memo / description | {', '.join(f'`{m}`' for m in memo)} |")
            if bank.get("note"):
                L.append(f"| Note | {bank['note']} |")
            L.append("")
        crypto = methods.get("crypto_usdt") or {}
        if crypto:
            L.append("**Crypto (USDT):**")
            L.append("")
            L.append("| Field | Value |")
            L.append("|---|---|")
            if crypto.get("wallet"):
                L.append(f"| Operator deposit wallet | `{crypto['wallet']}` |")
            if crypto.get("network"):
                L.append(f"| Network | {crypto['network']} |")
            if crypto.get("ttl_minutes"):
                L.append(f"| Address TTL | {crypto['ttl_minutes']} min |")
            if crypto.get("EXCLUDED_contract_base_rate"):
                L.append(f"| Excluded (base-rate) | {crypto['EXCLUDED_contract_base_rate']} |")
            L.append("")
        other = [k for k in methods if k not in ("vn_bank", "crypto_usdt")]
        for k in other:
            L.append(f"- **{k.replace('_', ' ').title()}:** {methods[k]}")
        if other:
            L.append("")

    # --- cluster expansion ---------------------------------------------------------------------
    ni = (cx.get("new_indicators") or {})
    if ni:
        L += ["## Cluster expansion (from inside the panel)", ""]
        doms = ni.get("domains") or {}
        for host, why in doms.items():
            L.append(f"- **`{host}`** — {why}")
        for label, key in (("Operator USDT wallet", "operator_wallet_usdt_trc20"),
                           ("Operator payee bank", "operator_payee_bank")):
            if ni.get(key):
                L.append(f"- **{label}:** `{ni[key]}`")
        for t in (ni.get("telegram") or []):
            L.append(f"- **Telegram:** {t}")
        if cx.get("cluster_basis"):
            L.append("")
            L.append(f"_Cluster basis: {cx['cluster_basis']}._")
        L.append("")

    # --- anti-forensics ------------------------------------------------------------------------
    if pm.get("anti_forensics"):
        L += ["## Operational security tell", "", f"- {pm['anti_forensics']}", ""]

    # --- evidence table ------------------------------------------------------------------------
    # DISTRIBUTED report: cite the verifiable SOURCE (the endpoint / method), never an internal
    # case-store path. Disk provenance is collection detail that stays case-side (evidence
    # standard: a reader must be able to re-check from the source, not a path on our machine).
    L += ["## Engagement evidence table", ""]
    L.append("| When (UTC) | Fact | Source |")
    L.append("|---|---|---|")
    for r in log:
        ts = r.get("ts", "")
        ev = r.get("event", "")
        if ev == "engagement_complete":
            L.append(f"| {ts} | Account created on operator panel | `POST /api/auth/register` (201) |")
        elif ev == "payment_walk":
            ms = "; ".join(r.get("methods", []))
            L.append(f"| {ts} | Payment methods: {ms} | authenticated deposit flow |")
        elif ev == "cluster_expansion":
            L.append(f"| {ts} | Estate + contacts enumerated | `/api/public/ecosystem-sites` |")
    L.append("")
    L.append("_Underlying panel captures (screenshots, rendered pages, response logs) are retained "
             "on file and available to authorised recipients on request._")
    L.append("")
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Render a case's engagement artifacts as a report section.")
    ap.add_argument("case", help="case name (reads cases/<case>/engage/)")
    ap.add_argument("-o", "--out", help="write the markdown here (default: stdout)")
    ap.add_argument("--append-to", help="append the section to this markdown file (e.g. the case assessment)")
    args = ap.parse_args(argv)

    section = build(args.case)
    if args.append_to:
        with open(args.append_to, "a", encoding="utf-8") as fh:
            fh.write("\n\n" + section + "\n")
        print(f"appended engagement section to {args.append_to}", file=sys.stderr)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(section)
        print(f"wrote {args.out}", file=sys.stderr)
    if not (args.out or args.append_to):
        print(section)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
