#!/usr/bin/env python3
"""wp_pgp — keyless PGP keyserver pivot.

Input ONE selector — an e-mail address, a key fingerprint (40 hex for v4, 64 hex for v6; spaces
and a leading `0x` are tolerated) or a long key id (16 hex) — and ask the public keyservers in
`references/pgp.json` (keys.openpgp.org VKS, keyserver.ubuntu.com HKP, and Proton's HKP for
Proton-hosted addresses only). Every source is free and keyless.

What comes back is parsed by a minimal stdlib OpenPGP packet reader (RFC 4880 / RFC 9580), not by
shelling out to gpg, so the tool runs on a machine without gnupg:

  * public-key / public-subkey packets -> version, algorithm, size or curve, creation time,
    fingerprint (v4 = SHA-1 over 0x99 || len16 || body; v6 = SHA-256 over 0x9B || len32 || body;
    v3 = MD5 over the RSA n || e), key id;
  * user ID packets -> raw UID plus its `Name (comment) <email>` split;
  * signature packets -> self-signature creation, key expiry, key flags, primary-UID flag,
    revocations, and the issuer key ids of THIRD-PARTY certifications (the web-of-trust pivot).
    Signatures are PARSED, NOT CRYPTOGRAPHICALLY VERIFIED — a keyserver can serve any bytes.

HKP `op=index&options=mr` machine-readable lines (`pub:` / `uid:`) are parsed too, because they
list every key a server holds for a search term, including ones whose `get` output is huge.

RULE 5 — ATTRIBUTION SAFETY. A UID is SELF-ASSERTED by whoever generated the key; only
keys.openpgp.org checks mailbox control, and only for the e-mail it serves. Every e-mail, name or
certifier key id this tool derives is emitted as a `rung: "lead"` pivot with a caveat — never a
KB edge, never an operator. A Proton key's creation time approximates the Proton account's
creation time (Proton generates the key at signup) — useful for a timeline, still a lead.

Tri-state per source, never raises: `found` True/False when the source answered, `found: None`
plus `error` when it could not be asked, `skipped` when the source cannot answer this selector.

CLI:
  python3 wp_pgp.py operator@example.com
  python3 wp_pgp.py "0123 4567 89AB CDEF 0123  4567 89AB CDEF 0123 4567" --json
  python3 wp_pgp.py --file key.asc --json          # offline: parse an armored key you already hold
"""
import argparse
import base64
import binascii
import datetime
import hashlib
import json
import os
import re
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from wp_refs import ref_path, load_ref  # noqa: E402 — reference DATA lives in references/*.json
try:
    from wp_net import fetch  # noqa: E402 — shared Android-UA / proxy-aware fetch
except Exception:             # parser stays usable offline even if the net layer cannot import
    fetch = None

# --- reference DATA (RULE 3): the fallback is the conservative minimum — the one VKS source and
#     the common algorithm ids — so the tool still answers if the JSON goes missing.
_PGP_FALLBACK = {
    "settings": {"timeout_seconds": 20, "max_body_bytes": 4000000, "max_certifiers_per_uid": 50},
    "sources": {"keys_openpgp_org": {
        "label": "keys.openpgp.org (VKS)", "kind": "vks",
        "by_email": "https://keys.openpgp.org/vks/v1/by-email/{email}",
        "by_fingerprint": "https://keys.openpgp.org/vks/v1/by-fingerprint/{fpr}",
        "by_keyid": "https://keys.openpgp.org/vks/v1/by-keyid/{keyid}"}},
    "pubkey_algorithms": {"1": "RSA", "17": "DSA", "18": "ECDH", "19": "ECDSA",
                          "22": "EdDSA-legacy", "25": "X25519", "27": "Ed25519"},
    "curve_oids": {"2b06010401da470f01": "Ed25519", "2b060104019755010501": "Curve25519",
                   "2a8648ce3d030107": "NIST P-256"},
    "fixed_key_bits": {"25": 255, "27": 255},
    "key_flags": {"1": "C", "2": "S", "4": "E", "8": "E", "32": "A"},
}
_REFS = load_ref(ref_path(__file__, "pgp.json"), _PGP_FALLBACK)
_SETTINGS = _REFS["settings"]
DEFAULT_TIMEOUT = int(_SETTINGS.get("timeout_seconds") or 20)
MAX_BODY = int(_SETTINGS.get("max_body_bytes") or 4000000)
MAX_CERTIFIERS = int(_SETTINGS.get("max_certifiers_per_uid") or 50)
SOURCES = _REFS["sources"]
ALGOS = {int(k): v for k, v in _REFS["pubkey_algorithms"].items()}
CURVES = dict(_REFS["curve_oids"])
FIXED_BITS = {int(k): int(v) for k, v in _REFS["fixed_key_bits"].items()}
KEY_FLAGS = {int(k): v for k, v in _REFS["key_flags"].items()}

UID_CAVEAT = ("PGP UIDs are self-asserted by the key's creator; a keyserver listing is not proof "
              "the named person or mailbox controls the key. Lead only — corroborate before any "
              "same-operator claim (RULE 5).")
PROTON_CAVEAT = ("Proton generates the address key at account signup, so the primary key's "
                 "creation time approximates the account's creation time — a key rotation or an "
                 "added address resets it. Timeline lead, not proof of who registered it.")
PROTON_DECOY_CAVEAT = ("Proton's HKP answers EVERY address on its domains with a well-formed key "
                       "(anti-enumeration decoys with plausible past creation dates), so a key "
                       "alone proves neither that the account exists nor when it was made. Only a "
                       "certification by a Proton CA UID (references/pgp.json -> ca_signer_uids) "
                       "corroborates a real address; without it the date is UNVERIFIED.")
SIG_CAVEAT = "Signatures are parsed, not cryptographically verified."

_EMAIL_RE = re.compile(r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$")
_UID_RE = re.compile(r"^\s*(?P<name>[^(<]*?)\s*(?:\((?P<comment>[^)]*)\))?\s*(?:<(?P<email>[^>]*)>)?\s*$")
_BARE_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


# =============================================================================== selector
def classify(selector: str):
    """-> (type, normalized). type in email | fingerprint | keyid | short_keyid | None."""
    s = (selector or "").strip()
    if _EMAIL_RE.match(s):
        return "email", s.lower()
    h = re.sub(r"\s+", "", s)
    if h.lower().startswith("0x"):
        h = h[2:]
    if re.fullmatch(r"[0-9A-Fa-f]+", h or "x"):
        h = h.upper()
        if len(h) in (40, 64):
            return "fingerprint", h
        if len(h) == 16:
            return "keyid", h
        if len(h) == 8:
            return "short_keyid", h
    return None, s


# =============================================================================== armor
def _crc24(data: bytes) -> int:
    crc = 0xB704CE
    for b in data:
        crc ^= b << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def dearmor(text: str):
    """Every `-----BEGIN PGP PUBLIC KEY BLOCK-----` block in `text` -> list of
    {"data": bytes, "crc_ok": True|False|None}. Malformed blocks are skipped, never raised."""
    out = []
    for m in re.finditer(r"-----BEGIN PGP PUBLIC KEY BLOCK-----(.*?)-----END PGP PUBLIC KEY BLOCK-----",
                         text or "", re.S):
        lines = [ln.strip() for ln in m.group(1).replace("\r", "").split("\n")]
        # armor headers ("Comment: ...") contain ':' which base64 never does, so they are dropped
        # line by line below — no reliance on the blank separator some servers omit
        crc_txt, body = None, []
        for ln in lines:
            if not ln:
                continue
            if ln.startswith("=") and len(ln) == 5:
                crc_txt = ln[1:]
                continue
            if ":" in ln:            # stray armor header
                continue
            body.append(ln)
        try:
            data = base64.b64decode("".join(body), validate=False)
        except (binascii.Error, ValueError):
            continue
        crc_ok = None
        if crc_txt:
            try:
                crc_ok = int.from_bytes(base64.b64decode(crc_txt), "big") == _crc24(data)
            except (binascii.Error, ValueError):
                crc_ok = False
        out.append({"data": data, "crc_ok": crc_ok})
    return out


# =============================================================================== packets
def iter_packets(data: bytes):
    """Yield (tag, body) for each OpenPGP packet; stops quietly at the first malformed header."""
    i, n = 0, len(data)
    while i < n:
        hdr = data[i]
        if not hdr & 0x80:
            return
        i += 1
        if hdr & 0x40:                                     # new format
            tag = hdr & 0x3F
            body = bytearray()
            while True:
                if i >= n:
                    return
                o = data[i]
                if o < 192:
                    ln, i = o, i + 1
                elif o < 224:
                    if i + 1 >= n:
                        return
                    ln, i = ((o - 192) << 8) + data[i + 1] + 192, i + 2
                elif o == 255:
                    if i + 4 >= n:
                        return
                    ln, i = int.from_bytes(data[i + 1:i + 5], "big"), i + 5
                else:                                      # partial body length
                    ln = 1 << (o & 0x1F)
                    body += data[i + 1:i + 1 + ln]
                    i += 1 + ln
                    continue
                body += data[i:i + ln]
                i += ln
                break
            yield tag, bytes(body)
        else:                                              # old format
            tag, lt = (hdr >> 2) & 0x0F, hdr & 0x03
            if lt == 3:
                ln = n - i
            else:
                w = (1, 2, 4)[lt]
                if i + w > n:
                    return
                ln, i = int.from_bytes(data[i:i + w], "big"), i + w
            yield tag, data[i:i + ln]
            i += ln


def _utc(ts):
    if not ts:
        return None
    try:
        return datetime.datetime.fromtimestamp(int(ts), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def _mpi(body: bytes, off: int):
    """-> (bits, value_bytes, next_offset)."""
    bits = int.from_bytes(body[off:off + 2], "big")
    ln = (bits + 7) // 8
    return bits, body[off + 2:off + 2 + ln], off + 2 + ln


def _key_material(algo: int, body: bytes, off: int):
    """Size/curve from the algorithm-specific material starting at `off`."""
    try:
        if algo in (1, 2, 3, 16, 17, 20):
            bits, _, _ = _mpi(body, off)
            return {"bits": bits}
        if algo in (18, 19, 22):
            oid = body[off + 1:off + 1 + body[off]].hex()
            return {"curve": CURVES.get(oid, "oid:" + oid)}
        if algo in FIXED_BITS:
            return {"bits": FIXED_BITS[algo], "curve": ALGOS.get(algo)}
    except IndexError:
        pass
    return {}


def parse_pubkey(body: bytes):
    """Public-key / public-subkey packet body -> dict, or None when the version is unsupported."""
    if len(body) < 6:
        return None
    ver = body[0]
    created = int.from_bytes(body[1:5], "big")
    out = {"version": ver, "created_ts": created, "created_utc": _utc(created)}
    if ver == 4:
        algo = body[5]
        fpr = hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).hexdigest().upper()
        out.update(fingerprint=fpr, key_id=fpr[-16:], algo_id=algo, **_key_material(algo, body, 6))
    elif ver in (5, 6):
        algo = body[5]
        prefix = b"\x9b" if ver == 6 else b"\x9a"
        fpr = hashlib.sha256(prefix + len(body).to_bytes(4, "big") + body).hexdigest().upper()
        out.update(fingerprint=fpr, key_id=fpr[:16], algo_id=algo, **_key_material(algo, body, 10))
    elif ver in (2, 3):
        if len(body) < 8:
            return None
        algo = body[7]
        out["algo_id"] = algo
        try:
            nbits, n, o = _mpi(body, 8)
            _, e, _ = _mpi(body, o)
            fpr = hashlib.md5(n + e).hexdigest().upper()
            out.update(fingerprint=fpr, key_id=n[-8:].hex().upper(), bits=nbits)
        except IndexError:
            return None
        days = int.from_bytes(body[5:7], "big")
        if days:
            out["expires_utc"] = _utc(created + days * 86400)
    else:
        return None
    out["algo"] = ALGOS.get(out.get("algo_id"), "algo:%s" % out.get("algo_id"))
    return out


def _subpackets(area: bytes):
    i, n = 0, len(area)
    while i < n:
        o = area[i]
        if o < 192:
            ln, i = o, i + 1
        elif o < 255:
            if i + 1 >= n:
                return
            ln, i = ((o - 192) << 8) + area[i + 1] + 192, i + 2
        else:
            ln, i = int.from_bytes(area[i + 1:i + 5], "big"), i + 5
        if ln < 1 or i + ln > n:
            return
        yield area[i] & 0x7F, area[i + 1:i + ln]
        i += ln


def parse_signature(body: bytes):
    """Signature packet body -> {type, created_ts, key_expiry_s, flags, primary_uid,
    issuer_keyid, issuer_fpr} (only the fields present). None on unsupported version."""
    if not body:
        return None
    ver = body[0]
    sig = {"version": ver}
    try:
        if ver == 3:
            sig["type"] = body[2]
            sig["created_ts"] = int.from_bytes(body[3:7], "big")
            sig["issuer_keyid"] = body[7:15].hex().upper()
            return sig
        if ver not in (4, 5, 6):
            return None
        sig["type"] = body[1]
        w = 2 if ver == 4 else 4
        hl = int.from_bytes(body[4:4 + w], "big")
        hashed = body[4 + w:4 + w + hl]
        o = 4 + w + hl
        ul = int.from_bytes(body[o:o + w], "big")
        unhashed = body[o + w:o + w + ul]
    except IndexError:
        return None
    for area, trusted in ((hashed, True), (unhashed, False)):
        for st, d in _subpackets(area):
            if st == 2 and trusted and len(d) >= 4:
                sig["created_ts"] = int.from_bytes(d[:4], "big")
            elif st == 9 and trusted and len(d) >= 4:
                sig["key_expiry_s"] = int.from_bytes(d[:4], "big")
            elif st == 27 and trusted and d:
                sig["flags"] = d[0]
            elif st == 25 and trusted and d:
                sig["primary_uid"] = bool(d[0])
            elif st == 28 and trusted and d:
                sig["signer_uid"] = d.decode("utf-8", "replace")
            elif st == 16 and len(d) >= 8:
                sig.setdefault("issuer_keyid", d[:8].hex().upper())
            elif st == 33 and len(d) >= 21:
                sig.setdefault("issuer_fpr", d[1:].hex().upper())
    if "issuer_fpr" in sig and "issuer_keyid" not in sig:
        f = sig["issuer_fpr"]
        sig["issuer_keyid"] = f[-16:] if len(f) == 40 else f[:16]
    return sig


def split_uid(uid: str):
    m = _UID_RE.match(uid or "")
    name = comment = email = None
    if m:
        name = (m.group("name") or "").strip() or None
        comment = (m.group("comment") or "").strip() or None
        email = (m.group("email") or "").strip() or None
    if not email:
        e = _BARE_EMAIL_RE.search(uid or "")
        if e:
            email = e.group(0)
            if name and email in name:
                name = None
    return {"name": name, "comment": comment, "email": email.lower() if email else None}


def _usage(flags):
    if flags is None:
        return None
    return "".join(sorted({v for b, v in KEY_FLAGS.items() if flags & b}, key="CSEA".index)) or None


def _is_self(sig, key):
    return (sig.get("issuer_fpr") == key["fingerprint"]
            or sig.get("issuer_keyid") == key["key_id"])


def _finish(key):
    """Fold collected signatures into the key/UID/subkey fields and drop internals."""
    sigs = key.pop("_sigs")
    newest_self = None
    for s in sigs:
        if not _is_self(s, key):
            continue
        if s.get("type") == 0x20:
            key["revoked"] = True
        elif s.get("type") == 0x1F and (newest_self is None or s.get("created_ts", 0) >= newest_self.get("created_ts", 0)):
            newest_self = s
    primary_self = None
    for u in key["uids"]:
        best = None
        certs, cert_uids = [], []
        for s in u.pop("_sigs"):
            t = s.get("type")
            if _is_self(s, key):
                if t == 0x30:
                    u["revoked"] = True
                elif t in (0x10, 0x11, 0x12, 0x13) and (best is None or s.get("created_ts", 0) >= best.get("created_ts", 0)):
                    best = s
            elif t in (0x10, 0x11, 0x12, 0x13) and s.get("issuer_keyid"):
                if s["issuer_keyid"] not in certs:
                    certs.append(s["issuer_keyid"])
                if s.get("signer_uid") and s["signer_uid"] not in cert_uids:
                    cert_uids.append(s["signer_uid"])
        u["self_sig_created_utc"] = _utc(best.get("created_ts")) if best else None
        u["primary"] = bool(best and best.get("primary_uid"))
        u["certifiers"] = certs[:MAX_CERTIFIERS]
        if cert_uids:
            u["certifier_uids"] = cert_uids[:MAX_CERTIFIERS]
        if len(certs) > MAX_CERTIFIERS:
            u["certifiers_truncated"] = len(certs)
        if best and (primary_self is None or u["primary"]):
            primary_self = best
    src = newest_self or primary_self
    if src:
        if src.get("key_expiry_s"):
            key["expires_utc"] = _utc(key["created_ts"] + src["key_expiry_s"])
        if src.get("flags") is not None:
            key["usage"] = _usage(src["flags"])
    for sk in key["subkeys"]:
        best = None
        for s in sk.pop("_sigs"):
            if not _is_self(s, key):
                continue
            if s.get("type") == 0x28:
                sk["revoked"] = True
            elif s.get("type") == 0x18 and (best is None or s.get("created_ts", 0) >= best.get("created_ts", 0)):
                best = s
        if best:
            if best.get("key_expiry_s"):
                sk["expires_utc"] = _utc(sk["created_ts"] + best["key_expiry_s"])
            if best.get("flags") is not None:
                sk["usage"] = _usage(best["flags"])
        sk.pop("created_ts", None)
    key.pop("created_ts", None)
    return key


def parse_keys(blob):
    """Armored text (str) or binary transferable keys (bytes) -> list of key dicts:
    {fingerprint, key_id, version, algo, bits|curve, created_utc, expires_utc?, usage?, revoked?,
     uids[{uid, name, comment, email, self_sig_created_utc, primary, revoked?, certifiers[]}],
     subkeys[{fingerprint, key_id, algo, bits|curve, created_utc, expires_utc?, usage?, revoked?}]}.
    Never raises; unparseable input yields []."""
    if isinstance(blob, (bytes, bytearray)):
        txt = blob.decode("utf-8", "replace") if b"-----BEGIN PGP" in blob else None
        chunks = [{"data": bytes(blob), "crc_ok": None}] if txt is None else dearmor(txt)
    else:
        chunks = dearmor(blob or "")
    keys = []
    for ch in chunks:
        cur, ctx = None, None
        try:
            for tag, body in iter_packets(ch["data"]):
                if tag == 6:
                    pk = parse_pubkey(body)
                    if cur:
                        keys.append(_finish(cur))
                    cur = None
                    if pk:
                        cur = dict(pk, uids=[], subkeys=[], _sigs=[])
                        if ch["crc_ok"] is False:
                            cur["armor_crc_ok"] = False
                        ctx = cur
                elif cur is None:
                    continue
                elif tag == 13:
                    uid = body.decode("utf-8", "replace")
                    ctx = dict({"uid": uid}, **split_uid(uid), _sigs=[])
                    cur["uids"].append(ctx)
                elif tag == 17:                            # user attribute (photo) — sigs ignored
                    cur["has_photo_id"] = True
                    ctx = {"_sigs": []}
                elif tag == 14:
                    sk = parse_pubkey(body)
                    ctx = dict(sk, _sigs=[]) if sk else {"_sigs": []}
                    if sk:
                        cur["subkeys"].append(ctx)
                elif tag == 2 and ctx is not None:
                    s = parse_signature(body)
                    if s:
                        ctx["_sigs"].append(s)
        except Exception:                                  # truncated/garbled tail: keep what parsed
            pass
        if cur:
            keys.append(_finish(cur))
    for k in keys:                                         # public field order
        for f in ("algo_id",):
            k.pop(f, None)
        for sk in k["subkeys"]:
            sk.pop("algo_id", None)
    return keys


# =============================================================================== HKP index
def parse_hkp_index(text: str):
    """HKP `op=index&options=mr` output -> [{fingerprint|key_id, algo, bits, created_utc,
    expires_utc, flags, uids[{uid, name, comment, email, created_utc}]}]."""
    out, cur = [], None
    for ln in (text or "").splitlines():
        f = ln.strip().split(":")
        if not f or f[0] not in ("pub", "uid"):
            continue
        f += [""] * 7
        if f[0] == "pub":
            kid = f[1].upper()
            cur = {"fingerprint" if len(kid) in (40, 64) else "key_id": kid,
                   "algo": ALGOS.get(int(f[2]), "algo:" + f[2]) if f[2].isdigit() else None,
                   "bits": int(f[3]) if f[3].isdigit() else None,
                   "created_utc": _utc(f[4]) if f[4].isdigit() else None,
                   "expires_utc": _utc(f[5]) if f[5].isdigit() else None,
                   "flags": f[6] or None, "uids": []}
            out.append(cur)
        elif cur is not None:
            uid = urllib.parse.unquote(f[1])
            cur["uids"].append(dict({"uid": uid}, **split_uid(uid),
                                    created_utc=_utc(f[2]) if f[2].isdigit() else None))
    return out


# =============================================================================== sources
def _get(url, timeout):
    """-> (status, text) or raises — the caller turns exceptions into a tri-state error."""
    if fetch is None:
        raise RuntimeError("wp_net.fetch unavailable")
    _, status, _, body = fetch(url, timeout=timeout)
    truncated = len(body or b"") > MAX_BODY
    return status, (body or b"")[:MAX_BODY].decode("utf-8", "replace"), truncated


def _matches(key, stype, norm):
    if stype == "email":
        return any(u.get("email") == norm for u in key.get("uids", []))
    ids = [key.get("fingerprint", "")] + [s.get("fingerprint", "") for s in key.get("subkeys", [])]
    if stype == "fingerprint":
        return norm in ids
    return any(i.endswith(norm) or i.startswith(norm) for i in ids if i)


def query_source(name, cfg, stype, norm, timeout=DEFAULT_TIMEOUT):
    res = {"source": name, "label": cfg.get("label", name), "found": None, "keys": []}
    only = cfg.get("only_email_domains")
    if only and (stype != "email" or norm.rsplit("@", 1)[-1] not in only):
        res["skipped"] = "source only answers e-mails on: " + ", ".join(only)
        return res
    q = urllib.parse.quote
    if cfg.get("kind") == "vks":
        tmpl = {"email": cfg.get("by_email"), "fingerprint": cfg.get("by_fingerprint"),
                "keyid": cfg.get("by_keyid")}.get(stype)
        if not tmpl:
            res["skipped"] = "no VKS endpoint for selector type %s" % stype
            return res
        url = tmpl.format(email=q(norm, safe="@"), fpr=q(norm), keyid=q(norm))
    else:
        search = norm if stype == "email" else "0x" + norm
        url = cfg.get("get", "").format(search=q(search, safe="@"))
    res["url"] = url
    try:
        status, text, trunc = _get(url, timeout)
    except Exception as e:                                 # network/TLS/proxy — never raise
        res["error"] = "%s: %s" % (type(e).__name__, e)
        return res
    res["http_status"] = status
    if trunc:
        res["truncated"] = True
    if status == 404:
        res["found"] = False
    elif status == 200:
        res["keys"] = parse_keys(text)
        res["found"] = bool(res["keys"])
        if not res["keys"] and "BEGIN PGP" in text:
            res["found"], res["error"] = None, "armored key returned but could not be parsed"
    else:
        res["error"] = "HTTP %s" % status
    for k in res["keys"]:
        k["matches_selector"] = _matches(k, stype, norm)
    if cfg.get("index"):
        iurl = cfg["index"].format(search=q(norm if stype == "email" else "0x" + norm, safe="@"))
        try:
            ist, itext, _ = _get(iurl, timeout)
            res["index"] = parse_hkp_index(itext) if ist == 200 else []
            if ist not in (200, 404):
                res["index_error"] = "HTTP %s" % ist
        except Exception as e:
            res["index"], res["index_error"] = None, "%s: %s" % (type(e).__name__, e)
    return res


def _merge(results):
    merged = {}
    for r in results:
        for k in r.get("keys") or []:
            fp = k.get("fingerprint")
            if not fp:
                continue
            m = merged.get(fp)
            if m is None:
                m = merged[fp] = json.loads(json.dumps(k))
                m["sources"] = []
            else:
                m["matches_selector"] = m.get("matches_selector") or k.get("matches_selector")
                have = {u["uid"]: u for u in m["uids"]}
                for u in k["uids"]:
                    if u["uid"] not in have:
                        m["uids"].append(u)
                    else:
                        for c in u.get("certifiers", []):
                            if c not in have[u["uid"]]["certifiers"]:
                                have[u["uid"]]["certifiers"].append(c)
                skf = {s.get("fingerprint") for s in m["subkeys"]}
                m["subkeys"] += [s for s in k["subkeys"] if s.get("fingerprint") not in skf]
                for f in ("expires_utc", "usage", "revoked"):
                    if f in k and f not in m:
                        m[f] = k[f]
            if r["source"] not in m["sources"]:
                m["sources"].append(r["source"])
    return list(merged.values())


def _pivots(keys, stype, norm):
    piv, seen = [], set()

    def add(p):
        sig = (p["type"], p["value"])
        if sig not in seen:
            seen.add(sig)
            piv.append(p)

    for k in keys:
        fp = k["fingerprint"]
        if stype != "fingerprint" or fp != norm:
            add({"type": "pgp_fingerprint", "value": fp, "rung": "fact", "sources": k["sources"],
                 "caveat": "Identifies the key a keyserver served for the selector; says nothing "
                           "about who generated it."})
        for u in k["uids"]:
            if u.get("email") and u["email"] != norm:
                add({"type": "email", "value": u["email"], "rung": "lead", "fingerprint": fp,
                     "sources": k["sources"], "caveat": UID_CAVEAT})
            if u.get("name"):
                add({"type": "person_name", "value": u["name"], "rung": "lead", "fingerprint": fp,
                     "sources": k["sources"], "caveat": UID_CAVEAT})
            for c in u.get("certifiers", []):
                add({"type": "pgp_certifier_keyid", "value": c, "rung": "lead", "fingerprint": fp,
                     "caveat": "A third party signed this UID (web of trust): an associate lead, "
                               "unverified signature, not an identity link."})
    return piv


def lookup(selector: str, timeout: int = DEFAULT_TIMEOUT, only_sources=None):
    """Query every configured keyserver for `selector`. Never raises."""
    stype, norm = classify(selector)
    out = {"selector": selector, "selector_type": stype, "normalized": norm,
           "sources": [], "keys": [], "pivots": [], "proton_account_age": None,
           "caveats": [UID_CAVEAT, SIG_CAVEAT]}
    if stype is None:
        out["error"] = "selector is not an e-mail, a 40/64-hex fingerprint or a 16-hex key id"
        return out
    if stype == "short_keyid":
        out["caveats"].append("32-bit short key ids collide trivially; HKP results for one may be "
                              "unrelated keys. Re-query by fingerprint.")
        stype = "keyid"
    for name, cfg in SOURCES.items():
        if only_sources and name not in only_sources:
            continue
        try:
            out["sources"].append(query_source(name, cfg, stype, norm, timeout))
        except Exception as e:                             # belt-and-braces: a parser bug is one source's error
            out["sources"].append({"source": name, "found": None, "keys": [],
                                   "error": "%s: %s" % (type(e).__name__, e)})
    out["keys"] = _merge(out["sources"])
    out["pivots"] = _pivots(out["keys"], stype, norm)
    for r in out["sources"]:
        cfg = SOURCES.get(r["source"], {})
        if r.get("found") and cfg.get("account_age_proxy"):
            ks = [k for k in r["keys"] if k.get("matches_selector")] or r["keys"]
            first = min((k["created_utc"] for k in ks if k.get("created_utc")), default=None)
            ca = {c.lower() for c in cfg.get("ca_signer_uids") or []}
            ca_hit = sorted({cu for k in ks for u in k["uids"] for cu in u.get("certifier_uids", [])
                             if split_uid(cu)["email"] in ca or cu.lower() in ca})
            if first:
                age = {"account_created_utc_approx": first, "source": r["source"],
                       "ca_certified_by": ca_hit or None, "caveat": PROTON_CAVEAT}
                if cfg.get("serves_decoy_keys") and not ca_hit:
                    age.update(rung="unverified", account_exists=None,
                               caveat=PROTON_CAVEAT + " " + PROTON_DECOY_CAVEAT)
                else:
                    age.update(rung="lead", account_exists=True if ca_hit else None)
                out["proton_account_age"] = age
    return out


def parse_file(path: str):
    """Offline: parse a local armored/binary key file into the same shape as `lookup`."""
    out = {"file": path, "keys": [], "pivots": [], "caveats": [UID_CAVEAT, SIG_CAVEAT]}
    try:
        with open(path, "rb") as fh:
            blob = fh.read(MAX_BODY)
    except OSError as e:
        out["error"] = str(e)
        return out
    keys = parse_keys(blob)
    for k in keys:
        k["sources"] = ["file"]
    out["keys"] = keys
    out["pivots"] = _pivots(keys, None, None)
    return out


# =============================================================================== CLI
def _print_text(res):
    if res.get("error"):
        print("error:", res["error"])
    for r in res.get("sources", []):
        state = "skipped" if r.get("skipped") else ("error: " + r["error"] if r.get("error") and r.get("found") is None
                                                    else ("found" if r.get("found") else "not found"))
        print("[%s] %s (%d key(s))" % (r.get("label", r["source"]), state, len(r.get("keys") or [])))
    for k in res.get("keys", []):
        size = k.get("bits") or k.get("curve") or ""
        print("\n%s  %s %s  created %s%s%s" % (k["fingerprint"], k.get("algo"), size, k.get("created_utc"),
                                              "  expires " + k["expires_utc"] if k.get("expires_utc") else "",
                                              "  REVOKED" if k.get("revoked") else ""))
        for u in k["uids"]:
            print("  uid  %s%s" % (u["uid"], "  (revoked)" if u.get("revoked") else ""))
        for s in k["subkeys"]:
            print("  sub  %s  %s %s  created %s" % (s.get("fingerprint"), s.get("algo"),
                                                    s.get("bits") or s.get("curve") or "", s.get("created_utc")))
    if res.get("proton_account_age"):
        pa = res["proton_account_age"]
        print("\nProton account created ~", pa["account_created_utc_approx"], "(%s)" % pa["rung"])
    leads = [p for p in res.get("pivots", []) if p["rung"] == "lead"]
    if leads:
        print("\nleads:")
        for p in leads:
            print("  %-20s %s" % (p["type"], p["value"]))


def main():
    ap = argparse.ArgumentParser(description="Keyless PGP keyserver pivot (VKS / HKP / Proton).")
    ap.add_argument("selector", nargs="?", help="e-mail, fingerprint (40/64 hex) or long key id (16 hex)")
    ap.add_argument("--file", help="parse a local armored/binary key instead of querying keyservers")
    ap.add_argument("--sources", help="comma-separated subset of references/pgp.json sources")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    ap.add_argument("--json", action="store_true", help="emit JSON")
    a = ap.parse_args()
    if not a.selector and not a.file:
        ap.error("give a selector or --file")
    if a.file:
        res = parse_file(a.file)
    else:
        only = [s.strip() for s in a.sources.split(",")] if a.sources else None
        res = lookup(a.selector, timeout=a.timeout, only_sources=only)
    if a.json:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    else:
        _print_text(res)


if __name__ == "__main__":
    main()
