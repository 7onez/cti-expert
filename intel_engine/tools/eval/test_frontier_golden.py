#!/usr/bin/env python3
"""Frontier output golden — propose() must not change frontier() byte-for-byte.

Builds the synthetic cases from intel_engine/tools/eval/cases/frontier_golden/*.json
(in-test TemporaryDirectory), dumps frontier(case, max_new=N), and diffs against the
checked-in golden. An empty diff is the gate: any drift in pending/candidates/
co_tenancy_leads/related_leads/subdomains/ips_pending/origin_ips is a fail.

A fixture with `"fake_cdn": true` runs against a stand-in CDN index: tracked fixtures must use
RFC 5737 documentation addresses, which the real index calls bogons, so without the stand-in no
origin IP could ever be pinned. It treats only 127/8, 10/8, 192.168/16 as bogons and 192.0.2.0/24
as a Cloudflare edge. Every fixture date is era-stable (live, undated, or years old), so the golden
does not drift with the calendar.
"""
from __future__ import annotations

import ipaddress
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.dirname(HERE)
sys.path.insert(0, TOOLS)
import case_state as CS  # noqa: E402

GOLDEN_DIR = os.path.join(HERE, "cases", "frontier_golden")


class _FakeCdn:
    EDGE = ipaddress.ip_network("192.0.2.0/24")

    @staticmethod
    def is_bogon(ip):
        a = ipaddress.ip_address(ip)
        return any(a in ipaddress.ip_network(n) for n in ("127.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16"))

    @classmethod
    def classify(cls, ip, idx):
        if ipaddress.ip_address(ip) in cls.EDGE:
            return {"ip": ip, "cdn": True, "provider": "cloudflare", "kind": "cdn"}
        return {"ip": ip, "cdn": False, "provider": None, "kind": "origin_candidate"}


def _with_fake_cdn(fn):
    """Run fn() with case_state and wp_origin_history on the stand-in index; restore after."""
    saved = (CS._oh._cdn, CS._cdn, list(CS._CDN_IDX))
    CS._oh._cdn = lambda: (_FakeCdn, {"fake": True})
    CS._cdn, CS._CDN_IDX[:] = _FakeCdn, [{"fake": True}]
    try:
        return fn()
    finally:
        CS._oh._cdn, CS._cdn, CS._CDN_IDX[:] = saved[0], saved[1], saved[2]


def _norm(obj):
    """Canonical JSON for comparison (sort_keys, stable separators)."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _build_case(tmp, blueprint):
    cdir = os.path.join(tmp, blueprint["name"])
    os.makedirs(os.path.join(cdir, "raw"), exist_ok=True)
    for host, obj in (blueprint.get("files") or {}).items():
        with open(os.path.join(cdir, "raw", f"{host}.json"), "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
    st = CS.load_state(cdir)
    for k, v in (blueprint.get("state") or {}).items():
        if v is not None:
            st[k] = v
    # Stable case id — frontier embeds st["case"]; temp paths must not enter the golden.
    st["case"] = blueprint.get("name") or st.get("case") or "CASE-0001"
    CS.save_state(cdir, st)
    return cdir


def check():
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    if not os.path.isdir(GOLDEN_DIR):
        ok(False, f"golden dir missing: {GOLDEN_DIR}")
        return passed, failed, out

    fixtures = sorted(
        f for f in os.listdir(GOLDEN_DIR)
        if f.endswith(".json") and not f.startswith(".")
    )
    ok(bool(fixtures), f"at least one frontier golden fixture ({len(fixtures)} found)")

    with tempfile.TemporaryDirectory() as tmp:
        for fn in fixtures:
            path = os.path.join(GOLDEN_DIR, fn)
            try:
                with open(path, encoding="utf-8") as fh:
                    bp = json.load(fh)
            except Exception as e:
                ok(False, f"{fn}: load failed ({e})")
                continue
            cdir = _build_case(tmp, bp)
            goldens = bp.get("goldens") or {}
            if not goldens:
                # accept max0/max8 keys at top level for lean fixtures
                goldens = {k: bp[k] for k in bp if k.startswith("max")}
            ok(bool(goldens), f"{bp.get('name', fn)}: has golden snapshots")
            for key, expected in sorted(goldens.items()):
                try:
                    mn = int(str(key).replace("max", "") or "0")
                except ValueError:
                    mn = 0
                got = (_with_fake_cdn(lambda: CS.frontier(cdir, max_new=mn)) if bp.get("fake_cdn")
                       else CS.frontier(cdir, max_new=mn))
                same = _norm(got) == _norm(expected)
                if not same:
                    # pinpoint first differing top-level key for the failure label
                    drift = []
                    for k in sorted(set(got) | set(expected)):
                        if _norm(got.get(k)) != _norm(expected.get(k)):
                            drift.append(k)
                    ok(False, f"{bp.get('name', fn)}/{key}: frontier drift in {drift}")
                else:
                    ok(True, f"{bp.get('name', fn)}/{key}: frontier byte-identical")

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for s, l in lines:
        print(f"  {'ok ' if s == 'ok' else '✗  '} {l}")
    sys.exit(1 if f else 0)
