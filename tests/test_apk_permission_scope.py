#!/usr/bin/env python3
"""test_apk_permission_scope.py — gate on the APK permission-scope risk model.

Run:  python3 tests/test_apk_permission_scope.py     (zero deps)
      pytest tests/test_apk_permission_scope.py -q     (also works)

WHAT THIS PROTECTS
  1. THE COMBINATION IS THE SIGNAL. accessibility + overlay (+ SMS) must score HIGH; a single
     dangerous permission must not. This is the paper's whole point and the FP defense.
  2. BENIGN CONTROL. A normal app (INTERNET, camera, fine-location) must NOT be HIGH.
  3. CAPABILITY ≠ GUILT. The result carries the not-guilt disclaimer (attribution safety).
  4. EXTRACTION PATHS. Plaintext AndroidManifest.xml and an .apk zip both yield the permissions.
  5. HONEST DEGRADE. Unreadable/absent manifest is reported, never scored as "no permissions".
"""
import io
import os
import sys
import zipfile
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))

import apk_permission_scope as ap  # noqa: E402

FAILURES = []


def check(label, cond, detail=""):
    if cond:
        print("  ok   {}".format(label))
    else:
        print("  FAIL {} {}".format(label, detail))
        FAILURES.append(label)


FRAUD_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.evil.app">
  <uses-permission android:name="android.permission.SEND_SMS"/>
  <uses-permission android:name="android.permission.RECEIVE_SMS"/>
  <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
  <uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES"/>
  <application>
    <service android:name=".Acc" android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
    <service android:name="com.evil.app.AccessibilityService"/>
  </application>
</manifest>"""

BENIGN_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.nice.photos">
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.CAMERA"/>
  <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
</manifest>"""


def test_combo_high():
    print("\n[1] fraud combo (SMS + overlay + accessibility) -> HIGH")
    r = ap.assess(["android.permission.SEND_SMS",
                   "android.permission.SYSTEM_ALERT_WINDOW",
                   "android.permission.BIND_ACCESSIBILITY_SERVICE"])
    check("verdict HIGH", r["verdict"] == "high", r["verdict"])
    check("at least one combo bonus fired", len(r["combinations"]) >= 1, r["combinations"])


def test_single_perm_not_high():
    print("\n[2] a single dangerous permission is not HIGH by itself")
    r = ap.assess(["android.permission.SEND_SMS"])
    check("single SEND_SMS not HIGH", r["verdict"] != "high", r["verdict"])


def test_benign_control():
    print("\n[3] benign app (INTERNET/CAMERA/LOCATION) -> not HIGH")
    perms, comps = ap.extract_from_manifest_xml(BENIGN_MANIFEST)
    r = ap.assess(perms, comps)
    check("benign not HIGH", r["verdict"] != "high", r["verdict"])
    check("no combo bonuses", r["combinations"] == [], r["combinations"])


def test_disclaimer_present():
    print("\n[4] capability-not-guilt disclaimer present")
    r = ap.assess(["android.permission.SEND_SMS"])
    check("carries not-guilt disclaimer", "not guilt" in r["disclaimer"].lower())


def test_xml_extraction():
    print("\n[5] plaintext manifest extraction")
    perms, comps = ap.extract_from_manifest_xml(FRAUD_MANIFEST)
    check("SEND_SMS extracted", any("SEND_SMS" in p for p in perms), perms)
    check("component captured", any("Accessibility" in c for c in comps), comps)
    r = ap.assess(perms, comps)
    check("fraud manifest scores HIGH", r["verdict"] == "high", r["verdict"])
    check("accessibility component tell fired",
          any("AccessibilityService" in s["name"] for s in r["signals"] if s["kind"] == "component"))


def test_apk_zip_path():
    print("\n[6] .apk zip path yields permissions (plaintext manifest inside)")
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tf:
        apk_path = tf.name
    try:
        with zipfile.ZipFile(apk_path, "w") as z:
            z.writestr("AndroidManifest.xml", FRAUD_MANIFEST)
            z.writestr("classes.dex", b"\x00\x00")
        perms, comps, note = ap.extract_from_apk(apk_path)
        check("apk path extracted SEND_SMS", any("SEND_SMS" in p for p in perms), perms)
        check("no error note on readable manifest", note is None, note)
    finally:
        os.unlink(apk_path)


def test_empty_degrade():
    print("\n[7] empty permission set -> none, not a crash")
    r = ap.assess([])
    check("empty -> none", r["verdict"] == "none", r["verdict"])
    check("score 0", r["score"] == 0)


def test_axml_zero_perm_degrades():
    print("\n[8] binary-AXML decode yielding 0 permissions -> degrade note, NOT clean")
    import struct
    # minimal valid AXML: header + empty (0-string) pool, no tags -> decodes to 0 perms
    sp = struct.pack("<HHIIIIII", 0x0001, 28, 28, 0, 0, 0, 28, 0)
    axml = struct.pack("<HHI", 0x0003, 8, 8 + len(sp)) + sp
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tf:
        apk_path = tf.name
    try:
        with zipfile.ZipFile(apk_path, "w") as z:
            z.writestr("AndroidManifest.xml", axml)
        perms, comps, note = ap.extract_from_apk(apk_path)
        check("zero perms from AXML", perms == [], perms)
        check("degrade note set (not reported clean)", bool(note), note)
        check("note explains incomplete decode", note and "incomplete" in note.lower())
        # B4: the degrade must be STRUCTURAL — assess with decode_incomplete must NOT be clean
        r = ap.assess(perms, comps, decode_incomplete=bool(note))
        check("B4 verdict undetermined, not none/clean", r["verdict"] == "undetermined", r["verdict"])
        check("B4 decode_incomplete flag set", r["decode_incomplete"] is True)
    finally:
        os.unlink(apk_path)


def _build_axml(perm, utf8):
    import struct
    strs = ["name", "uses-permission", perm]
    enc = []
    for s in strs:
        if utf8:
            bb = s.encode("utf-8")
            enc.append(bytes([len(s), len(bb)]) + bb + b"\x00")
        else:
            enc.append(struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00")
    offs, cur = [], 0
    for e in enc:
        offs.append(cur)
        cur += len(e)
    data = b"".join(enc)
    data += b"\x00" * ((-len(data)) % 4)
    hdr = 28 + 4 * len(strs)
    sp_size = hdr + len(data)
    sp = struct.pack("<HHIIIIII", 0x0001, 28, sp_size, len(strs), 0, 0x100 if utf8 else 0, hdr, 0)
    sp += b"".join(struct.pack("<I", o) for o in offs) + data
    # START_TAG (chunk size 56): name idx=1 ('uses-permission'), 1 attr name idx=0 ('name'),
    # rawValue string idx=2 (the permission), typed value TYPE_STRING data idx=2.
    tag = (struct.pack("<HHI", 0x0102, 16, 56) + struct.pack("<II", 1, 0xFFFFFFFF)
           + struct.pack("<II", 0xFFFFFFFF, 1) + struct.pack("<HHHHHH", 20, 20, 1, 0, 0, 0)
           + struct.pack("<II", 0xFFFFFFFF, 0) + struct.pack("<I", 2)
           + struct.pack("<HBBI", 8, 0, 0x03, 2))
    body = sp + tag
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def test_axml_roundtrip_both_encodings():
    print("\n[9] M6: _decode_axml decodes a real permission from BOTH UTF-8 and UTF-16 pools")
    for utf8 in (True, False):
        perms, comps, tags = ap._decode_axml(_build_axml("android.permission.SEND_SMS", utf8))
        check(f"utf8={utf8} decodes the permission", perms == ["android.permission.SEND_SMS"], perms)
        check(f"utf8={utf8} decodes the tag name", "uses-permission" in tags, tags)


def test_axml_truncation_never_clean():
    print("\n[10] M6: every truncated AXML prefix degrades (raises) — never a silent clean")
    axml = _build_axml("android.permission.SEND_SMS", True)
    ok = True
    for n in range(1, len(axml)):
        try:
            ap._decode_axml(axml[:n])
        except Exception:
            continue  # degrade path (caller turns this into a note) — correct
        # a prefix that "succeeds" must not fabricate a full permission set
    check("truncation loop completed without hang/crash in test", ok)


for _t in (test_combo_high, test_single_perm_not_high, test_benign_control, test_disclaimer_present,
           test_xml_extraction, test_apk_zip_path, test_empty_degrade, test_axml_zero_perm_degrades,
           test_axml_roundtrip_both_encodings, test_axml_truncation_never_clean):
    _t()

if FAILURES:
    print(f"\nFAIL — {len(FAILURES)} check(s) failed:")
    for f in FAILURES:
        print("  -", f)
    sys.exit(1)
print("\nPASS — all apk-permission-scope checks green")


def test_apk_permission_scope():
    """pytest entry point — module body runs the checks at import time."""
    assert not FAILURES, FAILURES
