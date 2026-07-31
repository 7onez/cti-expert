#!/usr/bin/env python3
"""Offline unit gate for BinaryPivot's packer / obfuscation detection (detect_protection).

Real packed samples can't be committed (OPSEC + size), so this builds tiny SYNTHETIC artifacts
that carry the exact static tells the detector keys on — a known Android-protector .so name, a
UPX PE section, a self-extractor signature, and a uniform-entropy blob — and asserts the verdict,
the KB tracker fold, and the pivot. Pure stdlib; deterministic (no randomness). Run standalone or
via run_eval.py.
"""
import io
import os
import struct
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))), "BinaryPivot", "tools"))
import analyze_artifact as bp  # noqa: E402


def _fake_apk(extra_names):
    """A minimal ZIP that detect_type() will call an 'apk' (AndroidManifest.xml + classes.dex)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00stub")   # not a real AXML; parser degrades
        z.writestr("classes.dex", b"dex\n035\x00" + b"A" * 2048)     # low-entropy stub
        for n in extra_names:
            z.writestr(n, b"\x00" * 5000)
    return buf.getvalue()


def _fake_pe(section_names):
    """A minimal PE just valid enough for _pe_sections() to read the section table."""
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    e = 0x80
    struct.pack_into("<I", buf, 0x3C, e)
    buf[e:e + 4] = b"PE\x00\x00"
    struct.pack_into("<H", buf, e + 4, 0x8664)          # machine x64
    struct.pack_into("<H", buf, e + 6, len(section_names))
    struct.pack_into("<H", buf, e + 20, 0)              # SizeOfOptionalHeader = 0
    sect = e + 24
    for i, nm in enumerate(section_names):
        buf[sect + i * 40: sect + i * 40 + 8] = nm.encode().ljust(8, b"\x00")
    return bytes(buf)


def check():
    """Return (passed, failed, [outcome lines])."""
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    # --- entropy math ---
    ok(bp._entropy(b"") == 0.0, "entropy of empty is 0")
    ok(bp._entropy(b"\x00" * 4096) == 0.0, "entropy of all-zero is 0")
    ok(bp._entropy(bytes(range(256)) * 16) >= 7.99, "entropy of uniform bytes ~8.0")

    # --- Android protector detected purely from a .so name ---
    apk = _fake_apk(["lib/arm64-v8a/libjiagu.so"])
    prot = bp.detect_protection(apk, "apk")
    names = [d["name"] for d in prot.get("detections", [])]
    ok("Qihoo 360 Jiagu" in names, "Jiagu .so → protector detected")
    ok(prot.get("packed") and prot.get("obfuscated"), "named protector ⇒ packed & obfuscated")

    # --- protector .so with a VERSIONED name (regex must tolerate dots) ---
    legu = _fake_apk(["lib/arm64-v8a/libshella-2.10.7.6.so"])
    plegu = bp.detect_protection(legu, "apk")
    ok(any(d["name"] == "Tencent Legu" for d in plegu.get("detections", [])),
       "versioned libshella-*.so → Tencent Legu")

    # --- a clean APK (normal dex, no protector) yields NO protection block (no 'signals' noise) ---
    ok(bp.detect_protection(_fake_apk([]), "apk") == {}, "clean apk ⇒ empty protection block")

    # --- encrypted asset payload (no named .so, just a high-entropy blob) ---
    apk2 = io.BytesIO()
    with zipfile.ZipFile(apk2, "w") as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00stub")
        z.writestr("classes.dex", b"dex\n035\x00" + b"A" * 2048)
        z.writestr("assets/payload.dat", bytes(range(256)) * 40)     # entropy ~8.0
    prot2 = bp.detect_protection(apk2.getvalue(), "apk")
    ok(any(d["name"] == "encrypted asset payload" for d in prot2["detections"]),
       "high-entropy asset → encrypted payload flagged")

    # --- UPX PE section ---
    pe = _fake_pe(["UPX0", "UPX1", ".rsrc"])
    protpe = bp.detect_protection(pe, "pe")
    ok(any(d["name"] == "UPX" for d in protpe["detections"]), "UPX0 section → UPX packer")
    ok(protpe.get("packed"), "UPX ⇒ packed")

    # --- installer signature (any kind; scanned before dispatch) ---
    inst = b"MZ" + b"\x00" * 200 + b"Nullsoft Install System v3.08" + b"\x00" * 200
    proti = bp.detect_protection(inst, "pe")
    ok(proti.get("installer") == "NSIS", "NSIS signature → installer=NSIS")

    # --- clean file yields nothing (no false positive) ---
    clean = bp.detect_protection(b"A" * 10000, "pe")
    ok(not clean.get("packed"), "low-entropy clean PE stub ⇒ not packed")

    # --- KB fold: named protector reaches trackers as the weak app_protector hint ---
    tr = bp.to_trackers({"protection": prot}, {})
    ok("Qihoo 360 Jiagu" in (tr.get("app_protector") or []), "protector folded into app_protector")
    # generic entropy verdicts must NOT become a shared indicator
    tr2 = bp.to_trackers({"protection": {"detections": [
        {"name": "high-entropy PE section", "type": "packer"},
        {"name": "encrypted classes.dex", "type": "protector"}]}}, {})
    ok(not tr2.get("app_protector"), "generic entropy verdicts stay out of trackers")

    # --- pivot + end-to-end analyze() on the synthetic apk ---
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
        f.write(apk)
        path = f.name
    try:
        res = bp.analyze(path)
        kinds = [p["kind"] for p in res["pivots"]]
        ok("binary:protection" in kinds, "analyze() emits a binary:protection pivot")
        ok(res["artifacts"]["binary"].get("protection", {}).get("packed"),
           "analyze() records protection.packed on the apk")
        bp.render_leads(res)   # must not raise with a protection block present
        ok(True, "render_leads renders a protected artifact without error")
    finally:
        os.unlink(path)

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for status, label in lines:
        print(f"  [{status:4s}] {label}")
    print(f"\n{p} passed, {f} failed")
    sys.exit(1 if f else 0)
