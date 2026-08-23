#!/usr/bin/env python3
"""
en_inbox.py — the KYC / email-confirmation helper: read the analyst's OWN puppet mailbox, wait for
the registration confirmation email, and pull the confirm/verify link out of it.

WHY THIS EXISTS
---------------
Most fraud funnels do not verify identity — a made-up username + password registers and you log
straight in (no inbox needed). But some gate signup on an email-confirmation click. For those, the
persona must use a REAL mailbox the analyst controls — one of a small PUPPET-INBOX POOL provisioned
ahead of time — and something has to fetch the confirmation link. That is all this module does.

WHAT IT DOES / DOES NOT DO
--------------------------
  * It READS a mailbox you own, over IMAP, and returns the confirmation URL. It NEVER sends mail,
    NEVER touches anyone else's inbox, and NEVER opens the link itself (en_engage does that in the
    browser session so the click comes from the research egress, not from here).
  * The match is corroborated against the TARGET DOMAIN, so an unrelated newsletter sitting in the
    same puppet inbox is not mistaken for the confirmation.
  * It never fabricates or uploads identity documents. Hard KYC (government ID / selfie) is out of
    scope by construction — a human decides whether such an engagement is in scope at all.

THE POOL IS CASE DATA (RULE 1)
------------------------------
The pool holds REAL credentials to mailboxes the analyst controls, so it is git-ignored operator
data: it lives ONLY at `ENGAGE_INBOX_POOL` (default `knowledge/engage_inboxes.json`, and knowledge/
is git-ignored), is referenced by PATH, and is NEVER written into the skill or a commit. Shape:

    [
      {"email": "puppet1@gmail.example", "imap_host": "imap.gmail.com", "imap_port": 993,
       "imap_user": "puppet1@gmail.example", "imap_password": "<app-password>", "in_use": false}
    ]

For Gmail this is an APP PASSWORD (IMAP enabled), not the account password. `claim` marks an inbox
in_use so two cases don't share one; `release` frees it.
"""
from __future__ import annotations

import argparse
import email
import imaplib
import json
import os
import re
import sys
import time
from email.header import decode_header
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from en_refs import load_ref, ref_path  # noqa: E402

_FALLBACK = {
    "kyc_confirmation": {
        "link_keywords": ["confirm", "verify", "activate", "validate"],
        "subject_markers": ["confirm", "verify", "activate", "welcome"],
        "link_path_hints": ["/confirm", "/verify", "/activate", "token=", "code="],
        "poll_timeout_s": 180, "poll_interval_s": 10,
    }
}
KYC = load_ref(ref_path(__file__, "engage.json"), _FALLBACK)["kyc_confirmation"]

_POOL_PATH = os.environ.get("ENGAGE_INBOX_POOL") or os.path.join(
    os.environ.get("INTEL_ROOT") or os.getcwd(), "knowledge", "engage_inboxes.json")

_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)


# --- pool management ----------------------------------------------------------------------------
def _load_pool():
    if not os.path.exists(_POOL_PATH):
        return None, (f"no puppet-inbox pool at {_POOL_PATH}. Create it (git-ignored) with entries "
                      f"{{email, imap_host, imap_port, imap_user, imap_password}} — see the module "
                      f"docstring. This file is analyst-provisioned case data and is never committed.")
    try:
        with open(_POOL_PATH, encoding="utf-8") as fh:
            pool = json.load(fh)
        if not isinstance(pool, list):
            return None, f"{_POOL_PATH} must be a JSON list of inbox objects"
        return pool, None
    except Exception as exc:
        return None, f"could not read {_POOL_PATH}: {exc}"


def _save_pool(pool):
    with open(_POOL_PATH, "w", encoding="utf-8") as fh:
        json.dump(pool, fh, indent=2)


def claim(address: str = None) -> dict:
    """Reserve a puppet inbox (by address, or the first free one) and mark it in_use."""
    pool, err = _load_pool()
    if err:
        return {"error": err}
    for box in pool:
        if address and box.get("email") != address:
            continue
        if address or not box.get("in_use"):
            box["in_use"] = True
            _save_pool(pool)
            return {"claimed": box.get("email"),
                    "note": "marked in_use; release() when the case closes and burn the account"}
    return {"error": ("no free puppet inbox" + (f" matching {address}" if address else "") +
                      " — add one to the pool or release a used one")}


def release(address: str) -> dict:
    pool, err = _load_pool()
    if err:
        return {"error": err}
    for box in pool:
        if box.get("email") == address:
            box["in_use"] = False
            _save_pool(pool)
            return {"released": address}
    return {"error": f"{address} not in pool"}


def _creds(address: str):
    pool, err = _load_pool()
    if err:
        return None, err
    for box in pool:
        if box.get("email") == address:
            return box, None
    return None, f"{address} not in pool"


# --- reading the confirmation -------------------------------------------------------------------
def _decode(s):
    if not s:
        return ""
    parts = decode_header(s)
    out = ""
    for txt, enc in parts:
        out += txt.decode(enc or "utf-8", "replace") if isinstance(txt, bytes) else txt
    return out


def _body_text(msg) -> str:
    chunks = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                try:
                    chunks.append(part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", "replace"))
                except Exception:
                    pass
    else:
        try:
            chunks.append(msg.get_payload(decode=True).decode(
                msg.get_content_charset() or "utf-8", "replace"))
        except Exception:
            pass
    return "\n".join(chunks)


def _pick_link(text: str, target_domain: str = "") -> str:
    """Choose the confirmation URL from an email body: prefer a link whose host matches the target
    and whose path looks like a confirm/verify link; fall back to any confirm-ish link."""
    links = _URL_RE.findall(text or "")
    kw = [k.lower() for k in KYC["link_keywords"]] + [h.lower() for h in KYC["link_path_hints"]]
    td = (target_domain or "").lower().lstrip("www.")

    def host(u):
        return (urlparse(u).netloc or "").lower()

    scored = []
    for u in links:
        lu = u.lower()
        s = 0
        if td and td in host(u):
            s += 3
        if any(k in lu for k in kw):
            s += 2
        if any(p in lu for p in [h.lower() for h in KYC["link_path_hints"]]):
            s += 2
        if s:
            scored.append((s, u))
    scored.sort(reverse=True)
    return scored[0][1] if scored else ""


def wait_confirm(address: str, target_domain: str = "", timeout_s: int = None,
                 interval_s: int = None) -> dict:
    """Poll the puppet inbox for the registration confirmation email and return its confirm link.
    Reads only; opening the link is en_engage's job (so the click comes from research egress)."""
    box, err = _creds(address)
    if err:
        return {"error": err}
    for k in ("imap_host", "imap_user", "imap_password"):
        if not box.get(k):
            return {"error": f"pool entry for {address} is missing {k}"}
    timeout_s = int(timeout_s or KYC.get("poll_timeout_s", 180))
    interval_s = int(interval_s or KYC.get("poll_interval_s", 10))
    subj_markers = [m.lower() for m in KYC["subject_markers"]]
    td = (target_domain or "").lower()

    deadline = None  # set on first successful connect; time.monotonic is allowed
    start = time.monotonic()
    seen_uids = set()
    while time.monotonic() - start < timeout_s:
        try:
            M = imaplib.IMAP4_SSL(box["imap_host"], int(box.get("imap_port", 993)))
            M.login(box["imap_user"], box["imap_password"])
            M.select("INBOX")
            typ, data = M.search(None, "UNSEEN")
            uids = (data[0].split() if data and data[0] else [])
            for uid in reversed(uids):
                if uid in seen_uids:
                    continue
                seen_uids.add(uid)
                typ, md = M.fetch(uid, "(RFC822)")
                if typ != "OK" or not md or not md[0]:
                    continue
                msg = email.message_from_bytes(md[0][1])
                subject = _decode(msg.get("Subject")).lower()
                frm = _decode(msg.get("From")).lower()
                body = _body_text(msg)
                relevant = (any(m in subject for m in subj_markers)
                            or (td and (td in frm or td in body.lower())))
                if not relevant:
                    continue
                link = _pick_link(body, target_domain)
                if link:
                    M.logout()
                    return {"confirmed_email_found": True, "confirm_link": link,
                            "from": _decode(msg.get("From")), "subject": _decode(msg.get("Subject")),
                            "note": ("link NOT opened here — hand it to en_engage so the click "
                                     "originates from the research egress, then log in")}
            M.logout()
        except Exception as exc:
            return {"error": f"IMAP error for {address}: {exc}"}
        time.sleep(interval_s)
    return {"confirmed_email_found": False,
            "note": (f"no confirmation email matched within {timeout_s}s. It may not require "
                     f"confirmation, or the mail is slow / filtered — check the inbox by hand.")}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Read a puppet inbox for a registration confirmation link.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("claim"); c.add_argument("--address")
    r = sub.add_parser("release"); r.add_argument("address")
    w = sub.add_parser("wait"); w.add_argument("address")
    w.add_argument("--target-domain", default="")
    w.add_argument("--timeout", type=int); w.add_argument("--interval", type=int)
    args = ap.parse_args(argv)

    if args.cmd == "claim":
        out = claim(args.address)
    elif args.cmd == "release":
        out = release(args.address)
    else:
        out = wait_confirm(args.address, args.target_domain, args.timeout, args.interval)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if not out.get("error") else 1


if __name__ == "__main__":
    raise SystemExit(main())
