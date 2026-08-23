#!/usr/bin/env python3
"""
en_persona.py — mint a SYNTHETIC research identity for an authorized engagement.

Engagement (en_engage.py) must never use a real person's details and must never reuse an identity
across cases (a reused persona links your own operations together for the adversary). This tool
generates a fresh, obviously-synthetic persona and writes it to the case so the engagement, the
evidence and the eventual burn are all traceable to one record.

WHAT IT DOES NOT DO
-------------------
It does not create an inbox, buy a number, or register anything. It produces the DATA a signup
form asks for. Email and phone are placeholders by default:

  * EMAIL — a plausible local-part on a domain you pass with `--email-domain` (a disposable inbox
    YOU control and dedicate to research). With no domain it emits `<local>@example-research.invalid`,
    which cannot receive mail on purpose — so if the form needs email verification you are forced to
    wire a real controlled inbox consciously, rather than the tool inventing a live third-party one.
  * PHONE — omitted unless `--with-phone`, and then a clearly non-routable placeholder. An SMS-OTP
    signup needs a real research number the analyst provisions; the tool will not fabricate a live one.

The name pool is deliberately generic and international; nothing here is a real individual. Keys in
`references/engage.json` are not consulted for the name pools (those are not case-tunable filters);
the policy this tool honours — synthetic-only, one-per-case — lives in `engagement_policy` there.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import string
import sys

# Generic, non-real given/family names spanning several regions. Not individuals — building blocks.
_GIVEN = ["Alex", "Sam", "Jordan", "Chris", "Taylor", "Minh", "Linh", "Wei", "Yan", "Ivan",
          "Olga", "Marco", "Sofia", "Omar", "Nadia", "Kenji", "Aria", "Diego", "Elena", "Ravi"]
_FAMILY = ["Carter", "Brooks", "Nguyen", "Tran", "Chen", "Wang", "Petrov", "Rossi", "Silva",
           "Khan", "Ivanova", "Muller", "Costa", "Reyes", "Sato", "Novak", "Haddad", "Park"]
_CITIES = ["Springfield", "Riverton", "Fairview", "Kingston", "Milton", "Ashford", "Bristol"]
_STREETS = ["Maple", "Oak", "Cedar", "Elm", "Pine", "Birch", "Walnut", "Chestnut"]


def _rng_choice(seq, r):
    return seq[r.randbelow(len(seq))]


class _R:
    """secrets-backed randbelow, or a deterministic stream when --seed is given (reproducible
    persona for a re-run without touching the operator twice with two identities)."""
    def __init__(self, seed=None):
        self._det = seed is not None
        if self._det:
            self._buf = hashlib.sha256(str(seed).encode()).digest()
            self._i = 0

    def randbelow(self, n):
        if not self._det:
            return secrets.randbelow(n)
        if self._i >= len(self._buf):
            self._buf = hashlib.sha256(self._buf).digest()
            self._i = 0
        b = self._buf[self._i]
        self._i += 1
        return b % n


def _password(r, length=16):
    alpha = string.ascii_letters + string.digits + "!@#$%^&*-_"
    # guarantee category coverage that registration validators demand
    base = [_rng_choice(string.ascii_uppercase, r), _rng_choice(string.ascii_lowercase, r),
            _rng_choice(string.digits, r), _rng_choice("!@#$%^&*-_", r)]
    base += [_rng_choice(alpha, r) for _ in range(length - len(base))]
    # shuffle
    for i in range(len(base) - 1, 0, -1):
        j = r.randbelow(i + 1)
        base[i], base[j] = base[j], base[i]
    return "".join(base)


def _claim_pool_inbox(address: str = None):
    """Draw a REAL controlled address from the git-ignored puppet-inbox pool (for email-gated
    signups). Returns (address, None) or (None, error). The pool itself is never read into the
    persona — only the address is, so the persona file carries no credentials."""
    try:
        import en_inbox
    except Exception as exc:  # noqa: BLE001
        return None, f"en_inbox unavailable: {exc}"
    res = en_inbox.claim(address)
    if res.get("error"):
        return None, res["error"]
    return res.get("claimed"), None


def generate(email_domain: str = None, with_phone: bool = False, seed=None,
             country: str = "US", pool_email: str = None) -> dict:
    r = _R(seed)
    given = _rng_choice(_GIVEN, r)
    family = _rng_choice(_FAMILY, r)
    n = 100 + r.randbelow(900)
    username = f"{given.lower()}.{family.lower()}{n}"
    local = f"{given.lower()}{family.lower()}{n}"
    if pool_email:
        email = pool_email
        email_note = ("REAL controlled inbox drawn from the puppet-inbox pool — deliverable, so an "
                      "email-gated signup can be confirmed with en_inbox. Burn it at case close.")
    elif email_domain:
        email = f"{local}@{email_domain.lstrip('@')}"
        email_note = "deliverable ONLY if you actually control this inbox — verify before you rely on OTP"
    else:
        email = f"{local}@example-research.invalid"
        email_note = ("NON-DELIVERABLE placeholder (.invalid). If the signup verifies email, pass "
                      "--email-domain <a disposable inbox you control> — the tool will not invent a "
                      "live third-party address.")
    persona = {
        "kind": "synthetic-research-persona",
        "full_name": f"{given} {family}",
        "first_name": given, "last_name": family,
        "username": username,
        "email": email, "email_note": email_note,
        "password": _password(r),
        "dob": f"{1985 + r.randbelow(15)}-0{1 + r.randbelow(9)}-1{r.randbelow(9)}",
        "country": country,
        "city": _rng_choice(_CITIES, r),
        "address": f"{100 + r.randbelow(900)} {_rng_choice(_STREETS, r)} St",
        "postal": f"{10000 + r.randbelow(89999)}",
        "_warnings": [
            "SYNTHETIC — do not reuse on anything real; do not reuse across cases.",
            "This persona is now known to any operator it registers with. Burn it after the case.",
        ],
    }
    if with_phone:
        # 555-01xx is the reserved fictional-US block; not routable on purpose.
        persona["phone"] = f"+1555010{r.randbelow(10)}{r.randbelow(10)}"
        persona["phone_note"] = ("Reserved fictional number, NOT routable. SMS-OTP needs a real "
                                 "research number the analyst provisions; the tool will not fabricate one.")
    return persona


def _save(persona: dict, case: str) -> str:
    """Persist the persona under the case (evidence + traceability). Never into the skill."""
    import datetime
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    root = os.environ.get("INTEL_ROOT") or os.getcwd()
    d = os.path.join(root, "cases", case, "engage")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, f"persona_{ts}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(persona, fh, indent=2, ensure_ascii=False)
    return path


def main(argv=None):
    ap = argparse.ArgumentParser(description="Generate a synthetic research persona for engagement.")
    ap.add_argument("--email-domain", help="a disposable inbox domain YOU control (for OTP)")
    ap.add_argument("--from-pool", nargs="?", const=True, metavar="ADDRESS",
                    help="draw a REAL controlled address from the puppet-inbox pool (optionally a "
                         "specific one) for an email-gated signup")
    ap.add_argument("--with-phone", action="store_true", help="include a placeholder phone")
    ap.add_argument("--country", default="US")
    ap.add_argument("--seed", help="deterministic persona (reproducible re-run, same identity)")
    ap.add_argument("--case", help="persist under cases/<case>/engage/ (recommended)")
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args(argv)

    pool_email = None
    if args.from_pool:
        addr = None if args.from_pool is True else args.from_pool
        pool_email, err = _claim_pool_inbox(addr)
        if err:
            print(f"[en_persona] pool inbox unavailable: {err}", file=sys.stderr)
            return 1
    persona = generate(args.email_domain, args.with_phone, args.seed, args.country, pool_email)
    if args.case:
        path = _save(persona, args.case)
        persona["_saved"] = path
        print(f"saved persona -> {path}", file=sys.stderr)
    print(json.dumps(persona, indent=2 if args.pretty else None, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
