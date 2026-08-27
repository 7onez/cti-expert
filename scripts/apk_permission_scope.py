#!/usr/bin/env python3
# cti-expert skill — APK permission-scope risk scoring (BinaryPivot extension).
"""apk_permission_scope.py — score an Android app's requested permission scope for
over-privilege / on-device-fraud risk, from its manifest alone.

Grounded in: Lakshmi Kandagadla Srinivasamurthy, Marc Dupuis (University of Washington) —
*"The 'Allow' Reflex: Permission-Scope Misinterpretation as a Socio-Technical Exposure in
Mobile Cybercrime"*, APWG eCrime 2026. The paper's premise: users grant scopes they don't
understand, and mobile cybercrime abuses exactly that gap. This turns an APK's declared
permissions/components into an auditable risk judgement — the combination is the signal, not
any single permission (banking/AV apps legitimately hold many dangerous permissions).

Offline, deterministic, keyless. Three input paths, all no-network:
  * `--permissions a,b,c`        — score a permission list directly (the pure core)
  * a plaintext AndroidManifest.xml (apktool/AOSP output) — parsed with stdlib xml.etree
  * a real .apk                  — zip → AndroidManifest.xml; plaintext or binary AXML
                                   (a compact stdlib AXML decoder handling BOTH UTF-16 and
                                   UTF-8 string pools, extracting permissions AND components)

DEGRADE-NOT-CLEAN: if the AXML decode fails or yields 0 permissions (a real APK almost always
requests INTERNET), the verdict is `undetermined` — NEVER `none`/clean. That is a structural
property of the result, not a free-text sidecar, so a `--json` consumer keying on `verdict`
cannot read an incomplete decode as an audited-clean app.

Attribution-safety: a high score flags *capability*, not guilt — a legitimate app can hold
these; the verdict names the risky combination and says so.

Usage:
  uv run apk_permission_scope.py app.apk
  uv run apk_permission_scope.py AndroidManifest.xml
  uv run apk_permission_scope.py --permissions SEND_SMS,BIND_ACCESSIBILITY_SERVICE,SYSTEM_ALERT_WINDOW
  uv run apk_permission_scope.py app.apk --json -o out.json

Exit codes: 0 = assessed, 4 = bad input, 5 = manifest unreadable (reported, not crashed).
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
import sys
import json
import zipfile
import argparse

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

# ---------------------------------------------------------- risk model (tunable)
PERM_WEIGHTS = {
    "SEND_SMS": 15, "RECEIVE_SMS": 15, "READ_SMS": 15, "WRITE_SMS": 10,
    "BIND_ACCESSIBILITY_SERVICE": 20, "ACCESSIBILITY": 20,
    "SYSTEM_ALERT_WINDOW": 15,
    "REQUEST_INSTALL_PACKAGES": 12,
    "BIND_DEVICE_ADMIN": 15, "DEVICE_ADMIN": 15,
    "READ_CONTACTS": 8, "WRITE_CONTACTS": 8,
    "RECORD_AUDIO": 10, "CAMERA": 6,
    "READ_CALL_LOG": 10, "WRITE_CALL_LOG": 10, "PROCESS_OUTGOING_CALLS": 10, "CALL_PHONE": 6,
    "QUERY_ALL_PACKAGES": 6, "PACKAGE_USAGE_STATS": 8, "GET_ACCOUNTS": 5,
    "READ_PHONE_STATE": 4, "READ_PHONE_NUMBERS": 5,
    "RECEIVE_BOOT_COMPLETED": 4, "FOREGROUND_SERVICE": 2, "WRITE_SETTINGS": 6,
    "MANAGE_EXTERNAL_STORAGE": 8, "ACCESS_FINE_LOCATION": 4, "ACCESS_BACKGROUND_LOCATION": 6,
    "DISABLE_KEYGUARD": 4,
}


def _combos(present):
    bonus = []
    has = lambda *names: any(n in present for n in names)
    acc = has("BIND_ACCESSIBILITY_SERVICE", "ACCESSIBILITY")
    overlay = has("SYSTEM_ALERT_WINDOW")
    sms = has("SEND_SMS", "RECEIVE_SMS", "READ_SMS")
    admin = has("BIND_DEVICE_ADMIN", "DEVICE_ADMIN")
    installer = has("REQUEST_INSTALL_PACKAGES")
    if acc and overlay:
        bonus.append((25, "accessibility + overlay — classic on-device UI-hijack / fraud toolkit"))
    if sms and (acc or overlay):
        bonus.append((20, "SMS access + UI control — OTP interception with on-screen manipulation"))
    if installer and acc:
        bonus.append((15, "install-packages + accessibility — self-installing / self-updating dropper"))
    if admin and (sms or acc):
        bonus.append((15, "device-admin + SMS/accessibility — anti-removal + on-device control"))
    return bonus


def _leaf(perm):
    p = (perm or "").strip()
    if not p:
        return ""
    return p.rsplit(".", 1)[-1].upper()


def assess(permissions, components=None, decode_incomplete=False):
    """Pure, deterministic risk model. decode_incomplete=True forces an `undetermined` verdict
    (a manifest we could not fully read is NOT a clean app)."""
    leaves, seen = [], set()
    for p in permissions or []:
        lf = _leaf(p)
        if lf and lf not in seen:
            seen.add(lf)
            leaves.append(lf)
    present = set(leaves)

    signals = []
    for lf in leaves:
        w = PERM_WEIGHTS.get(lf)
        if w:
            signals.append({"kind": "permission", "name": lf, "weight": w})
    for w, note in _combos(present):
        signals.append({"kind": "combo", "name": note, "weight": w})

    comps = [c for c in (components or []) if c]
    comp_low = " ".join(comps).lower()
    if "accessibilityservice" in comp_low:
        signals.append({"kind": "component", "name": "declares an AccessibilityService", "weight": 8})
    if "deviceadmin" in comp_low or "device_admin" in comp_low:
        signals.append({"kind": "component", "name": "declares a DeviceAdminReceiver", "weight": 8})

    score = min(100, sum(s["weight"] for s in signals))

    if decode_incomplete:
        verdict = "undetermined"
        rationale = ("manifest decode incomplete — permission scope NOT assessed; "
                     "this is not a clean result.")
    else:
        if score >= 40:
            verdict = "high"
        elif score >= 20:
            verdict = "medium"
        elif score > 0:
            verdict = "low"
        else:
            verdict = "none"
        dangerous = [s["name"] for s in signals if s["kind"] == "permission"]
        combos = [s["name"] for s in signals if s["kind"] == "combo"]
        rationale = (
            f"{len(dangerous)} dangerous/special permission(s); "
            f"{len(combos)} high-risk combination(s) -> {verdict} ({score}/100)."
            if signals else "No dangerous/special permissions in the manifest."
        )

    return {
        "verdict": verdict,
        "score": score,
        "decode_incomplete": bool(decode_incomplete),
        "declared_count": len(permissions or []),
        "unique_permission_leaves": len(leaves),
        "dangerous_permissions": [s["name"] for s in signals if s["kind"] == "permission"],
        "combinations": [s["name"] for s in signals if s["kind"] == "combo"],
        "signals": signals,
        "rationale": rationale,
        "disclaimer": "Scores capability, not guilt — legitimate apps (banking, AV, launchers) "
                      "can hold these permissions. The signal is the combination + absence of a "
                      "plausible purpose; corroborate with the app's stated function before reporting.",
    }


# --------------------------------------------------- manifest extraction (offline)
def extract_from_manifest_xml(text):
    """Parse a PLAINTEXT AndroidManifest.xml → (permissions, components). stdlib only."""
    import xml.etree.ElementTree as ET
    ANDROID = "{http://schemas.android.com/apk/res/android}"
    perms, comps = [], []
    root = ET.fromstring(text)
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        name = el.attrib.get(ANDROID + "name") or el.attrib.get("android:name") or el.attrib.get("name")
        if tag == "uses-permission" and name:
            perms.append(name)
        elif tag in ("service", "receiver", "activity") and name:
            comps.append(name)
    return perms, comps


def _decode_axml(data):
    """Compact Android binary-XML (AXML) decoder → (permissions, components, tag names).
    Handles BOTH UTF-16 and UTF-8 string pools. Attribute records are read using the header's
    declared attributeStart/attributeSize and the attributeCount is clamped to the chunk, and
    the android:name attribute is matched by name-index so a crafted manifest cannot inject
    permissions via an unrelated string-typed attribute. Raises on a structurally unexpected
    file so the caller degrades to a note rather than a false 'no permissions'."""
    import struct
    if len(data) < 8 or struct.unpack_from("<H", data, 0)[0] != 0x0003:  # RES_XML_TYPE
        raise ValueError("not AXML")
    off = 8
    if struct.unpack_from("<H", data, off)[0] != 0x0001:                 # RES_STRING_POOL_TYPE
        raise ValueError("no string pool")
    sp_size = struct.unpack_from("<I", data, off + 4)[0]
    string_count = struct.unpack_from("<I", data, off + 8)[0]
    flags = struct.unpack_from("<I", data, off + 16)[0]
    is_utf8 = bool(flags & 0x100)                                        # UTF8_FLAG
    strings_start = struct.unpack_from("<I", data, off + 20)[0]
    offs = [struct.unpack_from("<I", data, off + 28 + i * 4)[0] for i in range(string_count)]
    sbase = off + strings_start

    def _u16len(p):
        n = struct.unpack_from("<H", data, p)[0]
        if n & 0x8000:
            n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, p + 2)[0]
            return n, 4
        return n, 2

    def _u8len(p):
        b = data[p]
        if b & 0x80:
            return ((b & 0x7F) << 8) | data[p + 1], 2
        return b, 1

    strings = []
    for o in offs:
        p = sbase + o
        try:
            if is_utf8:
                _chars, c1 = _u8len(p)
                blen, c2 = _u8len(p + c1)
                start = p + c1 + c2
                strings.append(data[start:start + blen].decode("utf-8", "replace"))
            else:
                clen, c1 = _u16len(p)
                start = p + c1
                strings.append(data[start:start + clen * 2].decode("utf-16-le", "replace"))
        except Exception:
            strings.append("")

    def _str(i):
        return strings[i] if 0 <= i < len(strings) else ""

    pos = off + sp_size
    perms, comps, tags = [], [], []
    while pos + 8 <= len(data):
        ctype = struct.unpack_from("<H", data, pos)[0]
        csize = struct.unpack_from("<I", data, pos + 4)[0]
        if csize <= 0:
            break
        if ctype == 0x0102:  # START_TAG
            tagname = _str(struct.unpack_from("<I", data, pos + 20)[0])
            tags.append(tagname)
            astart = pos + 16 + struct.unpack_from("<H", data, pos + 24)[0]   # attributeStart
            stride = struct.unpack_from("<H", data, pos + 26)[0] or 20        # attributeSize
            ac = struct.unpack_from("<H", data, pos + 28)[0]
            ac = min(ac, max(0, (csize - (astart - pos)) // stride))          # clamp to chunk
            if tagname in ("uses-permission", "service", "receiver", "activity"):
                for i in range(ac):
                    a = astart + i * stride
                    name_i = struct.unpack_from("<I", data, a + 4)[0]
                    if _str(name_i) != "name":                                # android:name only
                        continue
                    val_str = struct.unpack_from("<I", data, a + 8)[0]
                    vtype = struct.unpack_from("<I", data, a + 12)[0] >> 24
                    val = ""
                    if val_str != 0xFFFFFFFF and 0 <= val_str < len(strings):
                        val = strings[val_str]
                    elif vtype == 0x03:  # TYPE_STRING typed value
                        val = _str(struct.unpack_from("<I", data, a + 16)[0])
                    if not val:
                        continue
                    if tagname == "uses-permission":
                        perms.append(val)
                    else:
                        comps.append(val)
        pos += csize
    return perms, comps, tags


_AXML_ZERO_PERM_NOTE = (
    "binary AXML decoded but yielded 0 permissions — the decode is likely incomplete "
    "(a real APK almost always requests at least INTERNET). NOT treated as a clean app; "
    "verify with a decoded manifest, androguard, or apktool."
)


def extract_from_apk(path):
    """Open an .apk, read AndroidManifest.xml (plaintext or binary AXML) → (perms, comps, note).
    A decode that fails or yields zero permissions returns a note; the caller must then treat
    the result as `undetermined`, never clean."""
    with zipfile.ZipFile(path) as z:
        raw = z.read("AndroidManifest.xml")
    head = raw[:64].lstrip()
    if head[:1] in (b"<", b"\xef"):
        perms, comps = extract_from_manifest_xml(raw.decode("utf-8", "replace"))
        return perms, comps, None
    try:
        perms, comps, tags = _decode_axml(raw)
    except Exception as e:  # noqa: BLE001
        return [], [], f"binary AXML decode failed ({e}); pass a decoded manifest or use androguard"
    note = None if perms else _AXML_ZERO_PERM_NOTE
    return perms, comps, note


def _fmt_text(r, note=None):
    head = "UNDETERMINED" if r["verdict"] == "undetermined" else r["verdict"].upper()
    out = [f"Verdict : {head}  (score {r['score']}/100)",
           f"Unique permission leaves: {r['unique_permission_leaves']} "
           f"(declared: {r['declared_count']})", "", r["rationale"]]
    if note:
        out.append("")
        out.append("NOTE: " + note)
    if r["signals"]:
        out.append("")
        out.append("Signals:")
        for s in r["signals"]:
            out.append(f"  [{s['kind']:<10}] +{s['weight']:<3} {s['name']}")
    out.append("")
    out.append("NOTE: " + r["disclaimer"])
    return "\n".join(out)


def _cli(argv):
    ap = argparse.ArgumentParser(
        description="Score an Android APK/manifest's permission scope for on-device-fraud risk (offline).")
    ap.add_argument("input", nargs="?", help=".apk path, AndroidManifest.xml path, or '-' for manifest on stdin")
    ap.add_argument("--permissions", help="comma-separated permission list (skip file parsing)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("-o", "--out")
    args = ap.parse_args(argv)

    note = None
    comps = []
    if args.permissions:
        perms = [p for p in args.permissions.split(",") if p.strip()]
    elif args.input:
        try:
            if args.input == "-":
                perms, comps = extract_from_manifest_xml(sys.stdin.read())
            elif zipfile.is_zipfile(args.input):
                perms, comps, note = extract_from_apk(args.input)
            else:
                with open(args.input, encoding="utf-8", errors="replace") as fh:
                    perms, comps = extract_from_manifest_xml(fh.read())
        except FileNotFoundError:
            print(f"error: file not found: {args.input}", file=sys.stderr)
            return 4
        except Exception as e:  # noqa: BLE001
            print(f"error: could not read manifest: {e}", file=sys.stderr)
            return 5
    else:
        print("error: provide an .apk / manifest / '-' , or --permissions", file=sys.stderr)
        return 4

    r = assess(perms, comps, decode_incomplete=bool(note))
    body = json.dumps({**r, "note": note}, indent=2, ensure_ascii=False) if args.json else _fmt_text(r, note)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(body + "\n")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(body)
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
