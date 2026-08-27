# APK Permission-Scope Risk Scoring

> **Module ID:** APK-PERM-001
> **Version:** 1.0.0
> **Phase:** Behavioral / Mobile Cybercrime Defense
> **Classification:** Android over-privilege / on-device-fraud capability scoring
> **Research basis:** Lakshmi Kandagadla Srinivasamurthy, Marc Dupuis (University of Washington) —
> *"The 'Allow' Reflex: Permission-Scope Misinterpretation as a Socio-Technical Exposure in
> Mobile Cybercrime"*, APWG eCrime 2026.

---

## 1. Overview

Scores an Android app's requested **permission scope** for on-device-fraud capability, from its
manifest alone. The eCrime paper's finding is that users grant scopes they don't understand and
mobile cybercrime abuses that gap; this module makes the capability explicit and auditable, and
extends BinaryPivot's existing APK static-IOC extraction (signing cert, package, C2 hosts).

The core principle — and the false-positive defense — is that **the combination is the signal, not
any single permission**. A banking or antivirus app legitimately holds SMS, accessibility, or
device-admin; the fraud tell is the *cluster* (accessibility + overlay + SMS) with no plausible
purpose. Scores are **capability, not guilt**: the output says so and never names an app as
malicious on scope alone.

**When to use:** on any collected/scam APK during BinaryPivot analysis.

---

## 2. Tool Inventory

| Priority | Tool | Purpose | Install |
|----------|------|---------|---------|
| Primary | `scripts/apk_permission_scope.py` | Offline permission-scope risk model + manifest extraction | none |
| Optional | androguard / apktool | richer AXML / resource decode for stubborn APKs | `uv pip install androguard` |
| Integrates | `intel_engine/BinaryPivot/*` | signing cert, package, C2/wallet IOC extraction | none |

Keyless, stdlib only. Three input paths: a permission list, a plaintext `AndroidManifest.xml`, or a
real `.apk` (zip → manifest; plaintext or a bundled compact binary-AXML decoder that degrades to a
note on any parse failure — never a false "no permissions").

---

## 3. Investigation Workflow

```
1. Obtain the APK (BinaryPivot collection / user-supplied)
2. Run apk_permission_scope.py on the .apk (or a decoded manifest)
3. Read the verdict + combinations:
     high   -> on-device-fraud capability cluster present (accessibility+overlay+SMS, dropper, etc.)
     medium -> notable dangerous scope; check against the app's stated purpose
     low    -> minor
4. Correlate with the app's claimed function; a mismatch (a "wallpaper" app with SMS+accessibility)
   is the reportable finding, not the permissions alone
5. Feed package name / signing cert / C2 (from BinaryPivot) into the case for clustering
```

---

## 4. CLI Commands & Expected Output

```bash
# A collected APK
python3 scripts/apk_permission_scope.py suspicious.apk

# A decoded manifest (apktool / AOSP output)
python3 scripts/apk_permission_scope.py AndroidManifest.xml

# Score a permission list directly (the pure core)
python3 scripts/apk_permission_scope.py --permissions SEND_SMS,BIND_ACCESSIBILITY_SERVICE,SYSTEM_ALERT_WINDOW

# JSON for the pipeline / IOC bundle
python3 scripts/apk_permission_scope.py suspicious.apk --json -o out.json
```

**Output:** `verdict` + score, `permission_count`, `dangerous_permissions`, `combinations`
(the fired fraud clusters), a per-signal list (kind / weight / name), rationale, and the
capability-not-guilt disclaimer.

---

## 5. Risk Model (default weights, tunable)

| Cluster / permission | Signal |
|----------------------|--------|
| accessibility + overlay | on-device UI-hijack / fraud toolkit (**+25 combo**) |
| SMS access + accessibility/overlay | OTP interception with on-screen manipulation (**+20**) |
| REQUEST_INSTALL_PACKAGES + accessibility | self-installing / self-updating dropper (**+15**) |
| device-admin + SMS/accessibility | anti-removal + on-device control (**+15**) |
| SEND/RECEIVE/READ_SMS | financial OTP theft surface |
| BIND_ACCESSIBILITY_SERVICE | on-device automation |
| SYSTEM_ALERT_WINDOW | overlay attacks |
| REQUEST_INSTALL_PACKAGES | dropper capability |
| BIND_DEVICE_ADMIN | anti-removal / control |
| READ/WRITE_CONTACTS, RECORD_AUDIO, CALL_LOG, QUERY_ALL_PACKAGES | surveillance surface |
| component: AccessibilityService / DeviceAdminReceiver declared | capability confirmed in code |

Verdict: `high` ≥ 40, `medium` ≥ 20, `low` > 0, `none` = 0. A special `undetermined` verdict is
returned when a binary-AXML manifest fails to decode or yields zero permissions — an unreadable
manifest is never reported as a clean app (the `--json` `verdict` field carries this, not just a
note). Both permissions **and** components (AccessibilityService / DeviceAdminReceiver) are
extracted from binary AXML, so the component tells fire on real APKs, not only decoded manifests.

---

## 6. Output Interpretation

- A **HIGH** with an accessibility+overlay+SMS cluster on an app whose stated purpose doesn't need
  it is a strong finding — the classic Android banking-trojan capability profile.
- A **HIGH** on a legitimate banking/AV app is expected — that is why the verdict is capability, and
  why correlation with the app's function is step 4, not optional.
- `combinations` is the part to quote in a report; a bare permission list is not.

---

## 7. Confidence Ratings

| Finding | Confidence | Notes |
|---------|-----------|-------|
| fraud cluster + purpose mismatch | HIGH | capability + no plausible reason |
| fraud cluster on a plausibly-legit app | MEDIUM | expected for banking/AV; corroborate |
| single dangerous permission | LOW | common; not on its own a finding |

---

## 8. Limitations

- **Manifest-only.** It does not analyze bytecode/behaviour — a permission requested may be unused,
  and runtime-requested permissions still appear in the manifest.
- **Binary AXML decode is best-effort** (stdlib); a heavily-obfuscated or exotic manifest degrades to
  a note recommending androguard, never a false "no permissions".
- **Capability, not intent.** Always correlate with the app's stated function before reporting.

---

## 9. Command Reference

### `apk_permission_scope.py <apk|manifest|-> | --permissions <list>`

**Input:** an `.apk`, a plaintext manifest, stdin, or a permission list.
**Process:** extract permissions/components → weighted model + combo bonuses → verdict.
**Output:** verdict, dangerous permissions, combinations, per-signal rationale, disclaimer.

Regression-tested by `tests/test_apk_permission_scope.py` (run in `scripts/audit.sh`), including the
combination-vs-single-permission logic and a benign-app false-positive control.

---

*APK Permission-Scope Module v1.0.0 — for authorized threat-intelligence use.*
