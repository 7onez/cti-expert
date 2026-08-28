#!/usr/bin/env python3
"""hash_id.py — identify what a hash IS before you go looking it up.

The question this answers is not academic. A 32-character hex string is MD5 *or* NTLM, and the
two send you to opposite places: MD5 is a file hash you look up in a malware corpus (VirusTotal,
MalwareBazaar); NTLM is CREDENTIAL material recovered from a host, which you must never paste
into a public sandbox. Submitting the second to the first is an irreversible disclosure of
someone's password hash to a third party. Length alone cannot separate them — context can, and
this tool asks for it rather than guessing.

Pure: no network, no keys, deterministic.

Usage:
  hash_id.py <hash> [<hash> ...]
  hash_id.py --stdin < hashes.txt
  hash_id.py <hash> --context file        # caller asserts it came from a FILE
  hash_id.py <hash> --context credential  # caller asserts it came from a CREDENTIAL store
"""
# /// script
# requires-python = ">=3.9"
# ///
import argparse
import json
import re
import sys

# (name, regex, kind, note). `kind`: file | credential | either | identifier
SIGNATURES = [
    ("CRC32",        r"^[0-9a-f]{8}$",  "identifier", "checksum, not a cryptographic hash"),
    ("MD5",          r"^[0-9a-f]{32}$", "file",       "classic file hash"),
    ("NTLM",         r"^[0-9a-f]{32}$", "credential", "Windows password hash — NEVER submit"),
    ("LM",           r"^[0-9a-f]{32}$", "credential", "legacy Windows hash — NEVER submit"),
    ("MD4",          r"^[0-9a-f]{32}$", "either",     "rare outside NTLM internals"),
    ("SHA-1",        r"^[0-9a-f]{40}$", "file",       "file hash; also git object id"),
    ("MySQL4.1+",    r"^\*[0-9A-F]{40}$", "credential", "MySQL password hash (leading *)"),
    ("SHA-224",      r"^[0-9a-f]{56}$", "file",       ""),
    ("SHA-256",      r"^[0-9a-f]{64}$", "file",       "the modern default for file hashes"),
    ("SHA-384",      r"^[0-9a-f]{96}$", "file",       ""),
    ("SHA-512",      r"^[0-9a-f]{128}$", "file",      ""),
    ("bcrypt",       r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$", "credential",
     "password hash — NEVER submit"),
    ("Argon2",       r"^\$argon2(id|i|d)\$", "credential", "password hash — NEVER submit"),
    ("scrypt",       r"^\$scrypt\$",    "credential", "password hash — NEVER submit"),
    ("SHA-512crypt", r"^\$6\$",         "credential", "/etc/shadow entry — NEVER submit"),
    ("SHA-256crypt", r"^\$5\$",         "credential", "/etc/shadow entry — NEVER submit"),
    ("MD5crypt",     r"^\$1\$",         "credential", "/etc/shadow entry — NEVER submit"),
    ("ssdeep",       r"^\d+:[A-Za-z0-9/+]+:[A-Za-z0-9/+]+$", "file", "fuzzy hash — compare, don't look up"),
    ("imphash",      r"^[0-9a-f]{32}$", "file",       "PE import hash — same shape as MD5"),
    ("TLSH",         r"^T1[0-9A-F]{70}$", "file",     "fuzzy hash"),
]

# Hashes that are safe to send to a third-party corpus, keyed by `kind`.
SUBMITTABLE = {"file": True, "identifier": True, "either": False, "credential": False}


def identify(value, context=None):
    """Return every signature a value could be, with the submit decision made explicit."""
    v = value.strip()
    lower = v.lower()
    cands = []
    for name, pat, kind, note in SIGNATURES:
        probe = v if pat.startswith("^\\$") or "A-F" in pat or pat.startswith("^\\d") else lower
        if re.match(pat, probe):
            cands.append({"algorithm": name, "kind": kind, "note": note})
    if not cands:
        return {"input": v, "length": len(v), "candidates": [],
                "verdict": "UNKNOWN", "safe_to_submit": False,
                "reason": "matches no known hash shape — do not treat it as a hash"}

    kinds = {c["kind"] for c in cands}
    if context:
        keep = [c for c in cands if c["kind"] in (context, "either")]
        if keep:
            # The caller has asserted provenance, so an "either" candidate resolves TO that
            # context — leaving it as "either" would keep the answer ambiguous forever and make
            # --context useless, which is the only thing that can break the 32-hex tie.
            for c in keep:
                if c["kind"] == "either":
                    c["kind"] = context
            cands, kinds = keep, {c["kind"] for c in keep}

    # AMBIGUOUS is a real verdict, not a failure. It is the whole reason this tool exists:
    # 32 hex is MD5 (submit freely) or NTLM (never submit), and only provenance separates them.
    if "credential" in kinds and len(kinds) > 1:
        verdict, safe = "AMBIGUOUS", False
        reason = ("could be a FILE hash or CREDENTIAL material — treat as credential until the "
                  "source is known. Re-run with --context file|credential once you can say where "
                  "it came from.")
    elif kinds == {"credential"}:
        verdict, safe = "CREDENTIAL", False
        reason = "credential material — never submit to a public sandbox or corpus"
    else:
        verdict = cands[0]["algorithm"]
        safe = all(SUBMITTABLE.get(c["kind"], False) for c in cands)
        reason = "file/identifier hash — safe to look up in a public corpus"

    return {"input": v, "length": len(v), "candidates": cands,
            "verdict": verdict, "safe_to_submit": safe, "reason": reason}


def main():
    ap = argparse.ArgumentParser(description="Identify a hash's algorithm before lookup.")
    ap.add_argument("hashes", nargs="*")
    ap.add_argument("--stdin", action="store_true", help="also read hashes from stdin")
    ap.add_argument("--context", choices=["file", "credential"],
                    help="assert where the hash came from — resolves the 32-hex ambiguity")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    vals = list(a.hashes)
    if a.stdin or not vals:
        vals += [ln.strip() for ln in sys.stdin if ln.strip()]
    if not vals:
        ap.error("no hashes given")

    results = [identify(v, a.context) for v in vals]
    blocked = [r for r in results if not r["safe_to_submit"]]
    out = {"results": results,
           "summary": {"total": len(results), "submittable": len(results) - len(blocked),
                       "blocked": len(blocked)}}
    txt = json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)
    print(f"{len(results)} hash(es): {len(results)-len(blocked)} safe to submit, "
          f"{len(blocked)} blocked", file=sys.stderr)
    for r in results:
        if not r["safe_to_submit"]:
            print(f"  ⛔ {r['input'][:24]}… → {r['verdict']}: {r['reason']}", file=sys.stderr)
    print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
