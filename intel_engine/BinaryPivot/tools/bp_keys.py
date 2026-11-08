#!/usr/bin/env python3
"""
bp_keys.py — key and certificate material in a leaked tree, deduplicated by SPKI hash.

The same key pair turns up in many FORMS across one project — a PKCS#8 private key in a .pem,
its PKCS#1 twin in a config, the public half as base64 DER in a JSON/YAML/XML/properties file,
an X.509 certificate wrapping it, an OpenSSH public line in authorized_keys. All of them reduce
to ONE SubjectPublicKeyInfo, so SHA-256(SPKI DER) is the dedupe key and the pivot: the same
SPKI in two leaks / two apps / a CT log means the same key material travelled between them.

Forms handled with a minimal stdlib DER walker (no crypto library):
  PEM: CERTIFICATE, PUBLIC KEY, RSA PUBLIC KEY, RSA PRIVATE KEY, EC PRIVATE KEY, PRIVATE KEY
       (PKCS#8: RSA / EC / Ed25519 / X25519 / Ed448), OPENSSH PRIVATE KEY (public blob)
  base64 DER inside text (JSON strings with \\n escapes included), raw .der/.cer/.crt files,
  OpenSSH public lines (ssh-rsa / ssh-ed25519 / ecdsa-sha2-nistp*).
Ed25519 private seeds without an embedded public key are derived (RFC 8032 scalar mult).
Forms that cannot be reduced without a crypto library or a password (encrypted PEM, PKCS#12,
JKS, an EC private key with no public point) are recorded with spki_sha256=null and a reason.

PRIVATE MATERIAL IS NEVER OUTPUT — only hashes, forms and member paths.
RULE 5: a shared key is a LEAD (rung 'lead'): sample/test keys are copied between unrelated
projects. Keys in references/leak_forensics.json benign_spki_sha256 are marked benign.

Usage:
  bp_keys.py <archive.zip|.tar|.tgz|DIR|FILE.pem> [--pretty]
"""
import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bp_refs  # noqa: E402
import bp_archive_time  # noqa: E402 — MemberSource (zip / tar / directory reader)

_FALLBACK = {
    "keys": {"max_scan_bytes": 2 << 20, "max_keys": 200, "max_occurrences": 50},
    "key_der_extensions": [".der", ".cer", ".crt"],
    "key_keystore_extensions": [".p12", ".pfx", ".jks", ".keystore"],
    "benign_spki_sha256": [],
}
_REF = bp_refs.load_ref(bp_refs.ref_path(__file__, "leak_forensics.json"), _FALLBACK)
_K = {**_FALLBACK["keys"], **(_REF.get("keys") or {})}
_DER_EXT = tuple(str(e).lower() for e in _REF.get("key_der_extensions") or [])
_STORE_EXT = tuple(str(e).lower() for e in _REF.get("key_keystore_extensions") or [])
_BENIGN = {str(h).lower() for h in _REF.get("benign_spki_sha256") or []}

CAVEAT = ("A shared key links the places it was copied to, not who copied it — sample and test "
          "keys travel between unrelated projects. Lead only; corroborate before attribution.")

# ----------------------------------------------------------------------------- OIDs (DER bodies)
_OID_RSA = bytes.fromhex("2a864886f70d010101")
_OID_EC = bytes.fromhex("2a8648ce3d0201")
_OID_ED25519 = bytes.fromhex("2b6570")
_OID_X25519 = bytes.fromhex("2b656e")
_OID_ED448 = bytes.fromhex("2b6571")
_OID_X448 = bytes.fromhex("2b656f")
_CURVES = {bytes.fromhex("2a8648ce3d030107"): "P-256", bytes.fromhex("2b81040022"): "P-384",
           bytes.fromhex("2b81040023"): "P-521", bytes.fromhex("2b8104000a"): "secp256k1"}
_SSH_CURVES = {"nistp256": bytes.fromhex("2a8648ce3d030107"),
               "nistp384": bytes.fromhex("2b81040022"), "nistp521": bytes.fromhex("2b81040023")}
_OKP = {_OID_ED25519: "ed25519", _OID_X25519: "x25519", _OID_ED448: "ed448", _OID_X448: "x448"}


# ----------------------------------------------------------------------------- DER walker
def _tlv(buf, off):
    """(tag, value_start, value_end) for the element at `off`; raises ValueError."""
    if off + 2 > len(buf):
        raise ValueError("short")
    tag, ln = buf[off], buf[off + 1]
    off += 2
    if ln & 0x80:
        n = ln & 0x7F
        if not 1 <= n <= 4 or off + n > len(buf):
            raise ValueError("bad length")
        ln = int.from_bytes(buf[off:off + n], "big")
        off += n
    if off + ln > len(buf):
        raise ValueError("overrun")
    return tag, off, off + ln


def _kids(buf, start, end):
    """[(tag, element_start, value_start, value_end)] of a constructed value."""
    out, off = [], start
    while off < end:
        tag, vs, ve = _tlv(buf, off)
        out.append((tag, off, vs, ve))
        off = ve
    if off != end:
        raise ValueError("trailing")
    return out


def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der(tag, value):
    return bytes([tag]) + _len(len(value)) + value


def _int_der(n):
    b = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big")
    return _der(0x02, b)


def _spki(alg_oid, params, pub_bits):
    alg = _der(0x06, alg_oid) + (params if params is not None else b"")
    return _der(0x30, _der(0x30, alg) + _der(0x03, b"\x00" + pub_bits))


def _rsa_spki(n_der, e_der):
    return _spki(_OID_RSA, b"\x05\x00", _der(0x30, n_der + e_der))


def _rsa_bits(n_der):
    _t, vs, ve = _tlv(n_der, 0)
    return int.from_bytes(n_der[vs:ve], "big").bit_length()


# ----------------------------------------------------------------------------- Ed25519 (RFC 8032)
_P = 2 ** 255 - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _ed_add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _ed_base():
    y = 4 * pow(5, _P - 2, _P) % _P
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if x & 1:
        x = _P - x
    return (x, y, 1, x * y % _P)


def ed25519_public(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little") & ((1 << 254) - 8) | (1 << 254)
    q, p = (0, 1, 1, 0), _ed_base()
    while a:
        if a & 1:
            q = _ed_add(q, p)
        p = _ed_add(p, p)
        a >>= 1
    zi = pow(q[2], _P - 2, _P)
    x, y = q[0] * zi % _P, q[1] * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


# ----------------------------------------------------------------------------- DER classification
def classify_der(der):
    """Reduce one DER blob to {kind, form, is_private, spki (bytes|None), reason?, bits?, curve?,
    cert_sha256?}. Returns None when the blob is not a recognised key/cert structure."""
    try:
        tag, vs, ve = _tlv(der, 0)
        if tag != 0x30 or ve != len(der):
            return None
        top = _kids(der, vs, ve)
    except ValueError:
        return None
    try:
        return (_as_spki(der, top) or _as_cert(der, top) or _as_pkcs8(der, top)
                or _as_pkcs1_priv(der, top) or _as_sec1(der, top, None) or _as_pkcs1_pub(der, top))
    except (ValueError, IndexError, struct.error):
        return None


def _alg(der, el):
    """AlgorithmIdentifier SEQUENCE -> (oid_bytes, params_element_bytes|None)."""
    tag, _s, vs, ve = el
    if tag != 0x30:
        raise ValueError("alg")
    k = _kids(der, vs, ve)
    if not k or k[0][0] != 0x06:
        raise ValueError("oid")
    oid = der[k[0][2]:k[0][3]]
    params = der[k[1][1]:k[1][3]] if len(k) > 1 else None
    return oid, params


def _describe_spki(spki):
    _t, vs, ve = _tlv(spki, 0)
    top = _kids(spki, vs, ve)
    oid, params = _alg(spki, top[0])
    bits_v = spki[top[1][2] + 1:top[1][3]]
    info = {}
    if oid == _OID_RSA:
        info["kind"] = "rsa"
        _t, s, e = _tlv(bits_v, 0)
        n = _kids(bits_v, s, e)[0]
        info["bits"] = int.from_bytes(bits_v[n[2]:n[3]], "big").bit_length()
    elif oid == _OID_EC:
        info["kind"] = "ec"
        if params and params[0] == 0x06:
            info["curve"] = _CURVES.get(params[2:], params[2:].hex())
    elif oid in _OKP:
        info["kind"] = _OKP[oid]
    else:
        info["kind"] = "oid:" + oid.hex()
    return info


def _as_spki(der, top):
    if len(top) != 2 or top[0][0] != 0x30 or top[1][0] != 0x03:
        return None
    _alg(der, top[0])
    out = {"form": "spki", "is_private": False, "spki": der}
    out.update(_describe_spki(der))
    return out


def _as_cert(der, top):
    if len(top) != 3 or top[0][0] != 0x30 or top[1][0] != 0x30 or top[2][0] != 0x03:
        return None
    tbs = _kids(der, top[0][2], top[0][3])
    i = 1 if tbs and tbs[0][0] == 0xA0 else 0     # [0] version
    # serial, signature, issuer, validity, subject, subjectPublicKeyInfo
    spki_el = tbs[i + 5]
    spki = der[spki_el[1]:spki_el[3]]
    out = {"form": "x509_certificate", "is_private": False, "spki": spki,
           "cert_sha256": hashlib.sha256(der).hexdigest()}
    validity = _kids(der, tbs[i + 3][2], tbs[i + 3][3])
    if len(validity) == 2:
        out["not_before"] = der[validity[0][2]:validity[0][3]].decode("ascii", "replace")
        out["not_after"] = der[validity[1][2]:validity[1][3]].decode("ascii", "replace")
    out["subject_cn"] = _cn(der, tbs[i + 4])
    out.update(_describe_spki(spki))
    return out


def _cn(der, name_el):
    try:
        for rdn in _kids(der, name_el[2], name_el[3]):
            for atv in _kids(der, rdn[2], rdn[3]):
                k = _kids(der, atv[2], atv[3])
                if der[k[0][2]:k[0][3]] == b"\x55\x04\x03":
                    return der[k[1][2]:k[1][3]].decode("utf-8", "replace")[:200]
    except (ValueError, IndexError):
        pass
    return None


def _as_pkcs8(der, top):
    if len(top) < 3 or top[0][0] != 0x02 or top[1][0] != 0x30 or top[2][0] != 0x04:
        return None
    oid, params = _alg(der, top[1])
    inner = der[top[2][2]:top[2][3]]
    if oid == _OID_RSA:
        r = _as_pkcs1_priv(inner, _kids(inner, *_tlv(inner, 0)[1:]))
        if r:
            r["form"] = "pkcs8"
        return r
    if oid == _OID_EC:
        _t, vs, ve = _tlv(inner, 0)
        r = _as_sec1(inner, _kids(inner, vs, ve), params)
        if r:
            r["form"] = "pkcs8"
        return r
    if oid in _OKP:
        kind = _OKP[oid]
        pub = None
        for t, _s, vs, ve in top[3:]:
            if t == 0x81:                              # [1] publicKey (OneAsymmetricKey v2)
                pub = der[vs + 1:ve]
        out = {"form": "pkcs8", "is_private": True, "kind": kind}
        if pub is None and kind == "ed25519":
            _t, vs, ve = _tlv(inner, 0)
            if ve - vs == 32:
                pub = ed25519_public(inner[vs:ve])
                out["derived"] = "ed25519 public key derived from the private seed (RFC 8032)"
        if pub is None:
            out.update(spki=None, reason=f"{kind} private key without an embedded public key; "
                                          "deriving it needs a crypto library")
        else:
            out["spki"] = _spki(oid, None, pub)
        return out
    return {"form": "pkcs8", "is_private": True, "kind": "oid:" + oid.hex(), "spki": None,
            "reason": "unsupported PKCS#8 algorithm"}


def _as_pkcs1_priv(der, top):
    if len(top) < 9 or any(t[0] != 0x02 for t in top[:9]) or der[top[0][2]:top[0][3]] not in (b"\x00", b"\x01"):
        return None
    n_der = der[top[1][1]:top[1][3]]
    e_der = der[top[2][1]:top[2][3]]
    return {"form": "pkcs1_private", "is_private": True, "kind": "rsa", "bits": _rsa_bits(n_der),
            "spki": _rsa_spki(n_der, e_der)}


def _as_pkcs1_pub(der, top):
    if len(top) != 2 or top[0][0] != 0x02 or top[1][0] != 0x02:
        return None
    n_der = der[top[0][1]:top[0][3]]
    e_der = der[top[1][1]:top[1][3]]
    if _rsa_bits(n_der) < 384:
        return None
    return {"form": "pkcs1_public", "is_private": False, "kind": "rsa", "bits": _rsa_bits(n_der),
            "spki": _rsa_spki(n_der, e_der)}


def _as_sec1(der, top, params):
    if len(top) < 2 or top[0][0] != 0x02 or der[top[0][2]:top[0][3]] != b"\x01" or top[1][0] != 0x04:
        return None
    pub = None
    for t, _s, vs, ve in top[2:]:
        if t == 0xA0:
            params = der[vs:ve]
        elif t == 0xA1:
            _bt, bvs, bve = _tlv(der, vs)
            pub = der[bvs + 1:bve]
    out = {"form": "sec1_private", "is_private": True, "kind": "ec"}
    if params and params[0] == 0x06:
        out["curve"] = _CURVES.get(params[2:], params[2:].hex())
    if pub is None or not params:
        out.update(spki=None, reason="EC private key without an embedded public point "
                                     "(deriving it needs a crypto library)")
    else:
        out["spki"] = _spki(_OID_EC, params, pub)
    return out


# ----------------------------------------------------------------------------- OpenSSH
def _ssh_str(b, off):
    n = struct.unpack(">I", b[off:off + 4])[0]
    if off + 4 + n > len(b):
        raise ValueError("ssh string")
    return b[off + 4:off + 4 + n], off + 4 + n


def ssh_blob_spki(blob):
    """OpenSSH public-key wire blob -> (spki, info) or (None, reason)."""
    typ, off = _ssh_str(blob, 0)
    t = typ.decode("ascii", "replace")
    if t == "ssh-rsa":
        e, off = _ssh_str(blob, off)
        n, off = _ssh_str(blob, off)
        n_der, e_der = _der(0x02, n), _der(0x02, e)
        return _rsa_spki(n_der, e_der), {"kind": "rsa", "bits": int.from_bytes(n, "big").bit_length()}
    if t == "ssh-ed25519":
        pub, _ = _ssh_str(blob, off)
        return _spki(_OID_ED25519, None, pub), {"kind": "ed25519"}
    if t.startswith("ecdsa-sha2-"):
        curve, off = _ssh_str(blob, off)
        q, _ = _ssh_str(blob, off)
        oid = _SSH_CURVES.get(curve.decode("ascii", "replace"))
        if oid:
            return _spki(_OID_EC, _der(0x06, oid), q), {"kind": "ec", "curve": _CURVES[oid]}
    return None, f"unsupported OpenSSH key type {t}"


def _openssh_private(blob):
    if not blob.startswith(b"openssh-key-v1\0"):
        return None
    off = len(b"openssh-key-v1\0")
    cipher, off = _ssh_str(blob, off)
    _kdf, off = _ssh_str(blob, off)
    _kdfopt, off = _ssh_str(blob, off)
    nkeys = struct.unpack(">I", blob[off:off + 4])[0]
    off += 4
    pub, off = _ssh_str(blob, off) if nkeys else (b"", off)
    spki, info = ssh_blob_spki(pub)
    out = {"form": "openssh_private", "is_private": True,
           "encrypted": cipher != b"none"}
    if isinstance(info, dict):
        out.update(info)
        out["spki"] = spki
    else:
        out.update(kind="unknown", spki=None, reason=info)
    return out


# ----------------------------------------------------------------------------- text scanning
_PEM_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]{3,40})-----(.*?)-----END \1-----", re.S)
_B64_DER_RE = re.compile(r"(?<![A-Za-z0-9+/=])(M[A-Za-z0-9+/]{38,}={0,2})(?![A-Za-z0-9+/=])")
_SSH_PUB_RE = re.compile(r"(?<![\w-])(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)) "
                         r"(AAAA[A-Za-z0-9+/]{20,}={0,2})")


def _b64(s):
    s = re.sub(r"[^A-Za-z0-9+/=]", "", s)
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None


def scan_text(text):
    """All key/cert findings in one text blob -> [finding dict, ...] with 'line'."""
    norm = (text.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\r", "")
            .replace("\\/", "/"))
    found = []

    def line_of(pos):
        return norm.count("\n", 0, pos) + 1

    spans = []
    for mo in _PEM_RE.finditer(norm):
        label, body = mo[1], mo[2]
        spans.append((mo.start(), mo.end()))
        if "Proc-Type:" in body and "ENCRYPTED" in body or label == "ENCRYPTED PRIVATE KEY":
            found.append({"form": "pem:" + label.lower().replace(" ", "_"), "is_private": True,
                          "kind": "unknown", "spki": None, "line": line_of(mo.start()),
                          "reason": "encrypted private key (needs the passphrase)",
                          "blob_sha256": hashlib.sha256(body.encode()).hexdigest()})
            continue
        if "Proc-Type:" in body:
            body = body.split("\n\n", 1)[-1]
        der = _b64(body)
        if not der:
            continue
        r = _openssh_private(der) if label == "OPENSSH PRIVATE KEY" else classify_der(der)
        if r is None and label in ("PGP PUBLIC KEY BLOCK", "PGP PRIVATE KEY BLOCK"):
            continue
        if r is None:
            continue
        r["form"] = "pem:" + r["form"]
        r["line"] = line_of(mo.start())
        if r.get("spki") is None:
            r["blob_sha256"] = hashlib.sha256(der).hexdigest()
        found.append(r)
    masked = list(norm)
    for s, e in spans:
        masked[s:e] = " " * (e - s)
    masked = "".join(masked)
    for mo in _B64_DER_RE.finditer(masked):
        der = _b64(mo[1])
        if not der or len(der) < 30:
            continue
        r = classify_der(der)
        if r:
            r["form"] = "base64_der:" + r["form"]
            r["line"] = line_of(mo.start())
            if r.get("spki") is None:
                r["blob_sha256"] = hashlib.sha256(der).hexdigest()
            found.append(r)
    for mo in _SSH_PUB_RE.finditer(masked):
        blob = _b64(mo[2])
        if not blob:
            continue
        try:
            spki, info = ssh_blob_spki(blob)
        except (ValueError, struct.error):
            continue
        if spki is None:
            continue
        found.append(dict(info, form="openssh_public", is_private=False, spki=spki,
                          line=line_of(mo.start())))
    return found


def _looks_binary(data):
    return b"\0" in data[:1024]


# ----------------------------------------------------------------------------- entry points
def analyze_source(src, extra_blobs=None):
    """Key/cert sweep over a MemberSource (+ optional [(label, bytes)]). {} when nothing found."""
    if src is None:
        return {}
    keys, order = {}, []
    stores = []
    cap = int(_K["max_scan_bytes"])

    def add(r, member):
        spki = r.pop("spki", None)
        sha = hashlib.sha256(spki).hexdigest() if spki else None
        key = sha or ("blob:" + r.get("blob_sha256", member + str(r.get("line"))))
        row = keys.get(key)
        if row is None:
            if len(keys) >= _K["max_keys"]:
                return
            row = keys[key] = {"kind": r.get("kind", "unknown"), "form": r["form"], "forms": [],
                               "spki_sha256": sha, "is_private": False, "occurrences": [],
                               "rung": "lead"}
            order.append(key)
            if not sha:
                row["reason"] = r.get("reason") or "SPKI not derivable"
            for k in ("bits", "curve"):
                if r.get(k):
                    row[k] = r[k]
        if r["form"] not in row["forms"]:
            row["forms"].append(r["form"])
        row["is_private"] = row["is_private"] or bool(r.get("is_private"))
        if r.get("cert_sha256"):
            certs = row.setdefault("certificates", [])
            if not any(c["sha256"] == r["cert_sha256"] for c in certs):
                certs.append({"sha256": r["cert_sha256"], "subject_cn": r.get("subject_cn"),
                              "not_before": r.get("not_before"), "not_after": r.get("not_after")})
        if r.get("derived"):
            row["derived"] = r["derived"]
        if r.get("encrypted"):
            row["encrypted"] = True
        if len(row["occurrences"]) < _K["max_occurrences"]:
            occ = {"member": member, "form": r["form"]}
            if r.get("line"):
                occ["line"] = r["line"]
            row["occurrences"].append(occ)

    members = src.members if hasattr(src, "members") else []
    for m in members:
        if m["is_dir"] or not m["size"]:
            continue
        name = m["name"]
        low = name.lower()
        if "/.git/objects/" in "/" + name:
            continue
        if low.endswith(_STORE_EXT):
            stores.append({"member": name, "size": m["size"], "spki_sha256": None,
                           "reason": "password-protected key container; open it with the "
                                     "password and a crypto tool to recover its keys"})
            continue
        if m["size"] > cap:
            continue
        data = src.read(name, cap)
        if not data:
            continue
        if low.endswith(_DER_EXT) and data[:1] == b"\x30":
            r = classify_der(data)
            if r:
                r["form"] = "der:" + r["form"]
                if r.get("spki") is None:
                    r["blob_sha256"] = hashlib.sha256(data).hexdigest()
                add(r, name)
                continue
        if _looks_binary(data) and b"-----BEGIN " not in data:
            continue
        for r in scan_text(data.decode("utf-8", "ignore")):
            add(r, name)
    for label, data in extra_blobs or []:
        for r in scan_text(data.decode("utf-8", "ignore")):
            add(r, label)

    rows = []
    for k in order:
        row = keys[k]
        if row["spki_sha256"] and row["spki_sha256"] in _BENIGN:
            row["benign"] = True
            row["note"] = "matches references/leak_forensics.json benign_spki_sha256 (public sample/test key)"
        row["occurrence_count"] = len(row["occurrences"])
        rows.append(row)
    rows.sort(key=lambda r: (-r["occurrence_count"], not r["is_private"]))
    if not (rows or stores):
        return {}
    out = {"keys": rows, "distinct": len(rows),
           "private_keys": sum(1 for r in rows if r["is_private"]),
           "shared_across_members": sum(1 for r in rows
                                        if len({o["member"] for o in r["occurrences"]}) > 1),
           "rung": "lead", "caveat": CAVEAT,
           "note": "Private key material is never output — only SPKI SHA-256 hashes and member paths."}
    if stores:
        out["keystores"] = stores[:50]
    return out


class _FileSource:
    """A single non-archive file viewed as a one-member source."""

    def __init__(self, path):
        self.path = path
        self.members = [{"name": os.path.basename(path), "size": os.path.getsize(path), "is_dir": False}]

    def read(self, _name, cap=None):
        with open(self.path, "rb") as fh:
            return fh.read(cap or -1)


def analyze(raw=None, path=None):
    """Tri-state: dict | {} | {'error': ...}."""
    try:
        src = bp_archive_time.open_source(raw=raw, path=path)
        if src is None and path and os.path.isfile(path):
            src = _FileSource(path)
        return analyze_source(src)
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"}


def main():
    ap = argparse.ArgumentParser(description="Key / certificate extraction with SPKI SHA-256 dedupe.")
    ap.add_argument("target", help="archive, directory or a single text/DER file")
    ap.add_argument("--pretty", action="store_true")
    a = ap.parse_args()
    res = analyze(path=a.target)
    print(json.dumps(res, indent=2 if a.pretty else None, ensure_ascii=False))
    return 0 if not res.get("error") else 2


if __name__ == "__main__":
    sys.exit(main())
