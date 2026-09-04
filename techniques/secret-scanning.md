# Secret Scanning Module

> **Module ID:** SEC-SCAN-001
> **Version:** 1.0.0
> **Phase:** 5 - Enhancement Modules
> **Classification:** Exposed Credential & API Key Discovery

---

## 1. Overview

Scans public repositories and web sources for accidentally committed secrets: API keys, tokens, passwords, private keys, and service credentials.

**When to use:** Org/repo reconnaissance, security posture checks, pre-engagement recon, authorized red-team asset discovery.

**Ethical boundary:** Never use discovered credentials for unauthorized access. Responsible disclosure is mandatory.

---

## 2. Tool Inventory

| Priority | Tool | Purpose | Install |
|----------|------|---------|---------|
| Primary | TruffleHog | 800+ detectors, auto-verification | `brew install trufflehog`, GitHub release binary, or `docker pull trufflesecurity/trufflehog` |
| Secondary | Gitleaks | Regex + entropy scanning | `brew install gitleaks` / download from GitHub releases |
| Tertiary | GitDorker | GitHub dork API queries | `git clone https://github.com/obheda12/GitDorker` |
| Manual | Google Dorks | Web-based public repo search | No install — browser-based |

---

## 3. Investigation Workflow

```
1. Identify target scope (org name, domain, repo URLs)
2. Run TruffleHog on known repos (--verified-only for actionable results)
3. Run Gitleaks on cloned repos for broader entropy-based coverage
4. Use GitDorker for GitHub search API across org
5. Apply manual Google dorks for web-exposed secrets
6. Deduplicate findings, classify severity
7. Document and prepare responsible disclosure report
```

---

## 4. CLI Commands & Expected Output

### TruffleHog — single repo scan
```bash
trufflehog github --repo=https://github.com/<org>/<repo> --json
```
**Verified secrets only (reduce false positives):**
```bash
trufflehog github --repo=https://github.com/<org>/<repo> --only-verified --json
```
**Org-wide scan:**
```bash
trufflehog github --org=<org_name> --only-verified --json 2>/dev/null | tee trufflehog-results.json
```
**Expected output (JSON):**
```json
{
  "SourceMetadata": { "Data": { "Github": { "repository": "...", "commit": "abc123", "file": "config.py", "line": 42 }}},
  "DetectorName": "AWS",
  "Verified": true,
  "Raw": "AKIA..."
}
```

### Gitleaks — cloned repo scan
```bash
git clone https://github.com/<org>/<repo> /tmp/target-repo
gitleaks detect --source=/tmp/target-repo --report-format=json --report-path=gitleaks-report.json
```
**Scan git history:**
```bash
gitleaks detect --source=/tmp/target-repo --log-opts="--all" --report-format=json --report-path=gitleaks-history.json
```
**Expected output:**
```json
[{
  "RuleID": "generic-api-key",
  "Commit": "abc123",
  "File": "src/config.js",
  "StartLine": 15,
  "Secret": "sk-...",
  "Author": "dev@example.com",
  "Date": "2024-01-10T09:22:00Z"
}]
```

### GitDorker — GitHub search API
```bash
cd GitDorker
python3 GitDorker.py -tf tokens.txt -q <domain.com> -d dorks/BHIS_toplevel_dorks.txt -o gitdorker-output.txt
```
**Requires:** Free GitHub token in `tokens.txt`

### Manual Google Dorks
```
site:github.com "<domain.com>" password OR api_key OR secret
site:github.com "<domain.com>" "BEGIN RSA PRIVATE KEY"
site:github.com "<domain.com>" "Authorization: Bearer"
site:github.com "<org_name>" ".env" OR "config.json" password
site:github.com "<domain.com>" "db_password" OR "database_url"
```

## 4a. GrayHatWarfare — open buckets & exposed files (`/secrets`, `/docleak`)

Beyond source-code secrets, `/secrets` and `/docleak` also search publicly readable object
storage (S3, Azure Blob, GCS, DO Spaces) and the files inside it via GrayHatWarfare
(`wp_buckets.py`). With `GRAYHATWARFARE_API_KEY` set the search is filterable and paginated; with
no key it degrades to the keyless `site:buckets.grayhatwarfare.com` dork (never an error).

**Pipeline lead (auto-fired):** the deterministic case pipeline emits a `grayhatwarfare:<apex>`
enrichment lead for every estate apex (closable via `enrichment-done`) and the cluster assessment
carries an *Exposure (leak surface — not attribution)* section for any bucket rows a collection
recorded. Bucket hits are graded EXPOSURE: a bucket carrying the brand label may be the brand's own,
a squatter's, or an unrelated tenant's — it is never a same-operator pivot and never seeds the frontier.

```bash
# buckets whose NAME matches the org/domain keyword (→ /secrets asset discovery)
uv run intel.py buckets buckets <org-or-domain> --limit 20
# exposed FILES matching the keyword (→ /docleak leaked-document discovery)
uv run intel.py buckets files <domain> --limit 20
```

**Grading:** an exposed bucket is graded **EXPOSURE**, never a same-operator cluster edge — two
sites in one public bucket share a hosting provider, not an operator. Findings feed the exposure
layer and responsible disclosure, not attribution edges.

---

## 5. Fallback Cascade

```
TruffleHog unavailable
  → Use Gitleaks (install from GitHub releases, no pip needed)

Gitleaks unavailable
  → Clone repo manually + grep patterns:
    grep -rE "(api_key|secret|password|token)\s*[=:]\s*['\"][^'\"]{8,}" /tmp/target-repo

GitHub API rate-limited
  → Use unauthenticated Google dorks
  → Use Sourcegraph: https://sourcegraph.com/search?q=<domain>+api_key

No tool available
  → Manual dork via browser:
    https://github.com/search?q=<domain>+api_key&type=code
```

---

## 6. Output Interpretation

**TruffleHog `Verified: true`** — credential tested against live API and confirmed valid. Treat as critical.

**TruffleHog `Verified: false`** — pattern matched but liveness unconfirmed. May be rotated or test data.

**Gitleaks findings in commit history** — even if removed from HEAD, credentials may still be valid. Check rotation date.

**Entropy score** — Gitleaks uses Shannon entropy. High entropy (>4.5) strings in assignments signal random keys. Lower entropy = likely human-readable (passwords, not tokens).

---

## 7. Confidence Ratings

| Finding Type | Confidence | Notes |
|--------------|-----------|-------|
| TruffleHog verified=true | CRITICAL | Live credential confirmed |
| TruffleHog verified=false | MEDIUM | May be rotated/test |
| Gitleaks high entropy match | MEDIUM | Needs manual review |
| Gitleaks rule-based match | MEDIUM | Context-dependent |
| Google dork — config file | HIGH | Context-dependent validity |
| GitDorker match | MEDIUM | Requires manual validation |

---

## 7a. Read-Only Credential Validation (liveness check)

When a secret is discovered during an **authorized** assessment, confirm whether it is *live* using only **read-only / identity** endpoints — never an endpoint that creates, modifies, deletes, or sends. This upgrades a finding from "pattern matched" (MEDIUM) to "confirmed live" (CRITICAL) with an account/scope for the disclosure report.

> **Discipline:** call an identity/whoami endpoint only; record `checked_at` (UTC), the truncated response, and the returned scope/account-ID; then **stop**. Do not enumerate resources or reuse the credential. On third-party assets, do not validate at all without written authorization — validation is a live API call that may alert the owner.

| Secret type | Read-only validation probe | Confirms |
|-------------|----------------------------|----------|
| AWS access key | `aws sts get-caller-identity` | Account ID + principal ARN |
| GitHub PAT | `curl -sI -H "Authorization: token <t>" https://api.github.com/user` → read `X-OAuth-Scopes` | Validity + granted scopes |
| Slack token | `curl -s -H "Authorization: Bearer xox...-" -X POST https://slack.com/api/auth.test` | Workspace + bot/user identity |
| Anthropic key | `curl -s -H "x-api-key: sk-ant-..." -H "anthropic-version: 2023-06-01" https://api.anthropic.com/v1/models` | Key validity |
| OpenAI key | `curl -s -H "Authorization: Bearer sk-..." https://api.openai.com/v1/models` | Key validity |
| Postman key | `curl -s -H "X-Api-Key: PMAK-..." https://api.getpostman.com/me` | Account identity |
| DataDog key | `curl -s -H "DD-API-KEY: ..." -H "DD-APPLICATION-KEY: ..." https://api.datadoghq.com/api/v1/validate` | Key validity |
| Stripe key | `curl -s https://api.stripe.com/v1/balance -u sk_live_...:` | Account + (do not move funds) |

A confirmed-live result → **CRITICAL**, attach account/scope evidence, and trigger the responsible-disclosure flow below immediately.

---

## 8. Limitations

- **TruffleHog verification** makes live API calls — may trigger security alerts at target
- **Rate limits:** GitHub Search API — 30 req/min (authenticated), 10/min (unauthenticated)
- **History gaps:** Force-pushed commits or repo deletions hide secrets from scanners
- **False positives:** Test credentials, placeholder values, example code inflate counts
- **Private repos:** Not accessible without credentials — public surface only
- **Rotation lag:** Credentials may appear in history but already rotated
- **TruffleHog docker** recommended over pip for latest detector rules

---

## 9. Command Reference

### `/secrets [target]`

**Input:** GitHub org name, repo URL, or domain
**Process:**
1. Run TruffleHog org scan with `--only-verified`
2. Clone top repos, run Gitleaks with `--log-opts="--all"`
3. Apply GitDorker with standard dork list
4. Deduplicate, classify by severity

**Severity Classification:**
- **Critical** — verified live credential (cloud keys, DB passwords, payment tokens)
- **High** — unverified match for high-value service (Stripe, AWS, GitHub PAT)
- **Medium** — generic API key or password, requires manual confirmation
- **Low** — partial match, test/example data, public keys only

**Output:** Sorted finding list with file, line, commit, secret type, severity, and responsible disclosure notes.

---

**Responsible Disclosure Reminder:**
If live credentials are found during authorized assessment, notify the asset owner privately before any further action. Do not exfiltrate, use, or publicly disclose active credentials.

---

*Secret Scanning Module v1.0.0*
*Part of Free OSINT Expert Skill - Phase 5*
*For authorized security assessment and educational purposes only*
