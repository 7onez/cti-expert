---
name: BinaryPivot
description: Static IOC extraction from binaries pulled off fraud/scam sites — the file half of a scam funnel (sideloaded Android APK, desktop "trading terminal" .exe/.dmg/.msi, bundled .jar/.zip). Downloads/opens the artifact, hashes it, and pulls the operator-clustering identifiers that survive re-skinning: APK signing-cert SHA-256, package name + permissions, embedded backend/C2 hosts, Firebase/appspot cloud tenant, S3 buckets, crypto wallets, Telegram/WhatsApp handles. Emits WebPivot-shaped pivot JSON so the SAME KB/case graph clusters the app with the web infrastructure. USE WHEN analyze APK, analyze binary, analyze exe, analyze installer, scam app, trading app, sideloaded APK, extract IOCs from file, malware IOCs, signing certificate, package name, APK backend, C2 endpoint, firebase project, mobile app analysis, reverse the app, what does this app connect to, pivot from a downloaded file, app download funnel.
---

> **OPSEC — this skill is portable/shared. Never write case data into it.** No real operator
> names, emails, domains, IPs, wallets, tracking IDs, hashes, or case IDs in this file, its
> workflows, tool code, or test fixtures. Investigation data lives only in the git-ignored
> `cases/` / `knowledge/` / `MEMORY/`. In examples use placeholders (`example.com`,
> `G-XXXXXXXXXX`, `CASE-0001`). See the repo-root `CLAUDE.md` for the full rule.

## 🚨 MANDATORY: Voice Notification (REQUIRED BEFORE ANY ACTION)

Send this BEFORE anything else when this skill is invoked:

```bash
curl -s -X POST http://localhost:8888/notify \
  -H "Content-Type: application/json" \
  -d '{"message": "Running the BinaryPivot skill to statically extract IOCs from a scam-site artifact"}' \
  > /dev/null 2>&1 &
```

Then output: `Running the **BinaryPivot** skill to ACTION...`

---

# BinaryPivot Skill

The sibling of **WebPivot**. WebPivot pivots on the *website*; BinaryPivot pivots on the *file the
website serves* — the sideloaded APK or desktop "terminal" that scam trading/investment funnels
push. It performs **static** extraction only (no detonation): download (or open a local file),
hash it, and pull the identifiers that cluster an operator's whole app portfolio even after they
re-skin the front end.

> ⚠️ **Authorization + safety first.** Only pull artifacts from infrastructure you are authorized
> to investigate, from **non-attributable egress** (research VPS/VPN). This tool never executes the
> sample — it is static analysis. For dynamic detonation use an isolated sandbox (MobSF, Triage,
> Any.Run), never your workstation.

## The tool — `tools/analyze_artifact.py`

**Zero required dependencies** (Python 3 stdlib). Optional accelerators used only if present:
`requests` (nicer download), `keytool` (APK signing cert — best pivot), `openssl` (cert fallback),
`file`/`strings`.

```bash
WP=~/.claude/skills/WebPivot ; BP=~/.claude/skills/BinaryPivot ; CASE=cases/<case>

# Pull an APK straight off the scam CDN and get ranked leads
python3 "$BP/tools/analyze_artifact.py" https://cdn.evil.example/app.apk --leads

# Analyze a local file, save the artifact + write case JSON (feeds the KB / graph)
python3 "$BP/tools/analyze_artifact.py" ./TradingPro.apk \
    --keep "$CASE/bin" -o "$CASE/raw/tradingpro.apk.json" --case <case>

# A desktop installer (Windows/macOS)
python3 "$BP/tools/analyze_artifact.py" https://cdn.evil.example/Setup.exe --leads
```

Flags: `--leads` (human-readable ranked pivots), `-o FILE` (full result JSON), `--pretty`
(pretty JSON to stdout), `--keep DIR` (save the downloaded file), `--case NAME` (stamped in meta).

## What it extracts

| Artifact | Why it's a pivot |
|---|---|
| **file sha256 / md5 / sha1** | VirusTotal / MalwareBazaar / Triage — prior sightings + sibling samples |
| **APK signing-cert SHA-256** | **strongest same-operator link** — clusters every app signed by one developer key; survives package/icon changes |
| **package name + version + permissions** | Koodous / APKPure listings; sensitive perms (SMS/CONTACTS/ACCESSIBILITY) flag the app's real intent |
| **embedded backend / C2 hosts + IP:port** | the app's real API — often *not* the download host; feed straight back into WebPivot |
| **Firebase project / appspot / storage bucket / API key** (google-services.json) | the operator's own Google Cloud tenant; RTDB may be world-readable (leaked leads/PII) |
| **S3 buckets, crypto wallets, Telegram/WhatsApp handles** | payout + recruitment infra reused across the portfolio |
| **embedded 2nd-stage payloads** (bundled dex/apk/dll/exe) | dropper behavior — a strong malicious tell |
| **PE compile timestamp / machine** (desktop installers) | build-time + arch fingerprint |
| **packer / protector / obfuscation** (entropy + section/member signatures) | *why* a sample's string sweep is thin — the real IOCs are encrypted inside; routes it to a dynamic sandbox. A **named** protector (UPX, VMProtect, Qihoo Jiagu, Tencent Legu, Ijiami…) is a **weak, kit-level** same-builder hint (`app_protector`) |

Supported containers: **APK/AAB** (manifest via a bundled pure-Python binary-XML parser, signing
cert via `keytool`/`openssl`), **JAR/ZIP**, **PE** (.exe/.dll), **Mach-O**, **ELF**, and a generic
`strings`-based sweep for anything else.

## How it clusters with the web case (the whole point)

The result is **WebPivot-shaped JSON** (`meta.host` + `artifacts.trackers{label:[values]}` +
`pivots[]`). The operator-clustering IOCs (`apk_signing_cert`, `apk_package`, `firebase_project`,
`app_backend_host`, `app_c2_endpoint`, wallets) are placed in `artifacts.trackers` so the **existing**
WebPivot KB ingester turns them into shared indicator nodes with no code changes:

```bash
# from the intel_engine project root — same ingest path as WebPivot
python3 tools/kb/ingest_webpivot.py --kb knowledge "$CASE"/raw/*.json
python3 tools/kb/query.py --kb knowledge --shared --min 2
```

A web domain and an APK that share a signing cert / backend host / Firebase project now land in the
**same cluster** in the case graph and the ICD-203 rollup — which is exactly how the app exposes the
operator behind a re-skinned website. Set `meta.host` to the **download host** (default when you pass
a URL) so the artifact anchors onto the site that served it.

## Workflow — APK/binary in a scam funnel

1. **WebPivot flags the file.** Running `pivot_extract.py` on the scam site emits `app:apk` /
   `app:desktop_installer` pivots whose first query is the exact BinaryPivot command to run.
2. **Acquire + extract.** Run `analyze_artifact.py <url>` from non-attributable egress. Save the
   file (`--keep`) and the JSON (`-o "$CASE/raw/<host>.json"`).
3. **Pivot the identifiers.** Start with the signing cert (Koodous `cert:`), then package name,
   Firebase project, then each embedded backend host — **invoke the `WebPivot` skill** on those
   hosts (`pivot_extract.py https://<backend-host> --leads`) to map their web infrastructure.
4. **Corroborate + cluster.** Ingest into the KB; a shared signing cert **and** a shared backend host
   between two apps (or an app and a website) is high-confidence common ownership.
5. **Report at the cluster level.** Roll the app + its web siblings into one assessment with WebPivot's
   `evidence_report.py` (see WebPivot `Workflows/Reporting.md`) — trigger: *"output full report for
   that cluster"*.

## Trigger patterns

- "analyze this APK / .exe / installer", "what IOCs are in this app"
- "what does this trading app connect to", "find its backend / C2"
- "get the signing cert / package name", "cluster these scam apps"
- "pivot from the downloaded file", "the site pushes an APK — dig into it"

## Notes on reliability

- **Signing cert** needs `keytool` (JDK) for v2/v3 schemes; `openssl` reads the v1 `META-INF/*.RSA`
  as a fallback. If both are absent the cert is skipped (everything else still runs).
- The binary `AndroidManifest.xml` is parsed with a **bundled pure-Python AXML decoder** (no aapt).
  On any parse error it degrades gracefully and the `strings`-based IOC sweep still runs.
- Host extraction is **noise-filtered**: reverse-DNS package names (`com.x.y`), class names,
  permission constants, and resource filenames (`config.json`, `libapp.so`) are rejected; hosts
  pulled from a real `http(s)://` URL are trusted.
- Static only — dead-code strings and library boilerplate can appear; corroborate a backend host by
  actually resolving/pivoting it before asserting it's live operator infra.
- **Packer / obfuscation triage** is entropy + signature based (`protection` block in the JSON;
  `⚠ PROTECTION:` line in `--leads`; a low-confidence `binary:protection` pivot). It detects UPX,
  the common PE protectors (VMProtect/Themida/ASPack/Enigma/MPRESS/…), Windows self-extractors
  (NSIS/Inno/InstallShield/7z-SFX), and the major Android app-protectors by their `.so`/asset
  signatures (Qihoo 360 Jiagu, Tencent Legu, Bangcle/SecNeo, Ijiami, Baidu, Alibaba, DexProtector,
  Promon, Virbox…), plus generic high-entropy `classes.dex`/asset blobs (encrypted-DEX packing).
  A **packed sample legitimately yields few IOCs** — that is the signal to detonate it in an
  isolated sandbox (MobSF/Triage), not to conclude the app is clean. A shared *named* protector is
  a **weak, kit-level** link (same builder/protection service), **not** proof of a common operator
  on its own — corroborate with a signing cert / backend host before clustering on it.
