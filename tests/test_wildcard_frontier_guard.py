#!/usr/bin/env python3
"""Regression: the harness frontier must not chase wildcard-DNS / label-recursion subdomains.

A `*.apex` zone answers every fabricated label, so the subdomain enumerators (validin_subs /
securitytrails / censys_cert) keep returning the same handful of labels recombined
(a.b.apex, b.b.apex, c.b.apex), and each collected synthetic host spawns more — an unbounded
frontier that never converges. orchestrator._wildcard_recursion caps re-seeding to genuine direct
subdomains of a known apex.

The helpers are extracted by AST from orchestrator.py and exec'd in isolation, so this test needs
NO third-party deps (orchestrator imports the Agent-SDK, absent under the system python audit.sh
uses). Pins the real source without importing the heavy module.

Zero deps:  python3 tests/test_wildcard_frontier_guard.py
No case data — only synthetic placeholder hosts (CLAUDE.md RULE 5).
"""
import ast
import os
import sys

ORCH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "intel_engine", "harness", "orchestrator.py")

FAILURES = []


def check(label, got, want):
    if got != want:
        FAILURES.append(f"{label}: got {got!r}, want {want!r}")


def _load_helpers():
    """Exec _MAX_SUB_DEPTH + the guard functions from orchestrator.py."""
    mod = ast.parse(open(ORCH, encoding="utf-8").read())
    want_fns = {"_has_repeated_label", "_apex_set", "_too_deep", "_wildcard_recursion"}
    body = []
    for n in mod.body:
        if isinstance(n, ast.Assign) and any(
                getattr(t, "id", None) == "_MAX_SUB_DEPTH" for t in n.targets):
            body.append(n)
        elif isinstance(n, ast.FunctionDef) and n.name in want_fns:
            body.append(n)
    found = {n.name for n in body if isinstance(n, ast.FunctionDef)}
    if found != want_fns:
        raise SystemExit(f"guard functions missing from orchestrator.py: {want_fns - found}")
    ns = {"os": os}
    exec(compile(ast.Module(body=body, type_ignores=[]), "<guards>", "exec"), ns)
    return ns


def main():
    ns = _load_helpers()
    apex_set = ns["_apex_set"]
    wr = ns["_wildcard_recursion"]

    known = {"kit-apex.example", "mail.kit-apex.example",
             "portal.kit-apex.example", "assets.kit-apex.example"}
    apexes = apex_set(known)
    check("apex resolves to the registrable root only", apexes, {"kit-apex.example"})

    keep = [  # genuine direct subdomains + the apex itself must pass (reject == False)
        "kit-apex.example",
        "mail.kit-apex.example",
        "portal.kit-apex.example",
        "unrelated-sibling.example",       # under no known apex -> other guards decide, not this one
    ]
    drop = [  # wildcard / label-recursion artifacts must be rejected (reject == True)
        "portal.mail.kit-apex.example",
        "mail.mail.kit-apex.example",
        "portal.portal.kit-apex.example",
        "assets.portal.kit-apex.example",
        "mail.mail.mail.kit-apex.example",
    ]
    for h in keep:
        check(f"keep {h}", wr(h, apexes), False)
    for h in drop:
        check(f"drop {h}", wr(h, apexes), True)

    # SOURCE-SCOPING: the depth cap is applied ONLY to subdomain-enumeration sources
    # (validin_subs / securitytrails). Cert-SAN / IP-co-tenant sources apply _has_repeated_label
    # alone, so an operator-chosen depth-2 host like login.secure.brand.example survives on those
    # paths but a wildcard-recombined depth-2 host is dropped on the enumeration path.
    rep = ns["_has_repeated_label"]
    too_deep = ns["_too_deep"]
    brand = {"brand.example"}
    check("cert/co-tenant policy keeps depth-2 non-repeated host",
          rep("login.secure.brand.example"), False)
    check("enumeration policy drops depth-2 host", too_deep("login.secure.brand.example", brand), True)
    check("enumeration policy keeps depth-1 host", too_deep("secure.brand.example", brand), False)
    check("combined guard drops enumeration junk", wr("portal.mail.kit-apex.example", apexes), True)

    # a repeated adjacent label is junk even under an unknown apex (defence in depth, every source)
    check("repeated label under unknown apex", wr("api.api.some-other.example", set()), True)
    check("repeated label flagged by the global check too", rep("api.api.some-other.example"), True)

    if FAILURES:
        print("FAIL:")
        for f in FAILURES:
            print("  -", f)
        sys.exit(1)
    print("ok - wildcard frontier guard")


if __name__ == "__main__":
    main()
