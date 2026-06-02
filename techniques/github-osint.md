# GitHub OSINT Module

> **Module ID:** GITHUB-OSINT-001
> **Version:** 1.0.0
> **Classification:** GitHub user, organization, repository, code, and metadata reconnaissance
> **Source inspiration:** Precious Vincent / D4rk_Intel, "GitHub OSINT: The Ultimate Reconnaissance Methodology Guide"

---

## 1. Overview

Use this module when a target has a GitHub username, organization, repository URL, domain, email, project name, or suspected developer footprint. It expands beyond secret scanning into profile intelligence, organization structure, repository inventory, code search, commit metadata, collaboration networks, fork/branch history, and reporting.

**Ethical boundary:** collect only public GitHub data or data the user is authorized to access. Never use discovered credentials, never bypass privacy controls, and respect GitHub API/search rate limits.

---

## 2. Reconnaissance Framework

1. **Target identification** — normalize handles, org names, repo URLs, domains, emails, project names.
2. **User and organization profiling** — capture public profile, org metadata, followers/following, visible members.
3. **Repository enumeration** — list repos, languages, stars/forks, licenses, issues, releases, branches, contributors.
4. **Code analysis and pattern recognition** — search configs, CI/CD, dependency files, docs, schemas, API examples, secrets indicators.
5. **Metadata and history collection** — commits, authorship emails, timestamps, working-hour patterns, ownership areas.
6. **Correlation and analysis** — link GitHub entities to domains, emails, social profiles, infrastructure, leaks, and case subjects.
7. **Reporting and documentation** — preserve URLs, timestamps, API responses, confidence ratings, risk, and remediation.

---

## 3. User and Organization Discovery

### User profile snapshot

```bash
# Public profile fields, no authentication required for basic lookups
curl -s "https://api.github.com/users/USERNAME" | jq '{login,id,node_id,name,company,blog,location,email,bio,twitter_username,hireable,public_repos,public_gists,followers,following,created_at,updated_at}'

# GitHub CLI equivalent
gh api users/USERNAME --jq '{login,name,company,location,public_repos,followers,following,created_at,updated_at}'
```

**Capture:** account creation date, update date, public repo count, gists, profile bio, location, company, blog/social links, follower/following counts.

### Social graph pivots

```bash
gh api users/USERNAME/followers --paginate --jq '.[].login'
gh api users/USERNAME/following --paginate --jq '.[].login'
```

Use followers/following as **connection leads**, not proof of relationship. Corroborate with commits, shared repos, org membership, mentions, or off-platform sources.

### Organization profile and visible members

```bash
gh api orgs/ORG --jq '{login,name,company,email,blog,location,description,public_repos,followers,created_at,updated_at}'
gh api orgs/ORG/members --paginate --jq '.[].login'
```

**Org intelligence:** public member list, likely employees, repo ownership, technology preferences, project maturity, external collaborators, partner orgs, and development workflow style.

**Note:** Teams, some members, and private org data require authorization. Log access gaps instead of treating them as blockers.

---

## 4. Repository Intelligence Gathering

### Repository discovery

```bash
# Keyword/domain/org discovery
gh search repos "TARGET" --json fullName,description,language,stargazersCount,forksCount,updatedAt,isFork,isArchived,url

# API fallback
curl -s "https://api.github.com/search/repositories?q=TARGET" | jq '.items[] | {full_name,description,language,stargazers_count,forks_count,updated_at,license,open_issues_count,html_url}'
```

### Repository inventory endpoints

```bash
gh api repos/OWNER/REPO --jq '{full_name,description,language,license,stargazers_count,forks_count,open_issues_count,created_at,updated_at,pushed_at,default_branch}'
gh api repos/OWNER/REPO/contents --paginate
gh api repos/OWNER/REPO/branches --paginate --jq '.[].name'
gh api repos/OWNER/REPO/contributors --paginate --jq '.[] | {login,contributions}'
gh api repos/OWNER/REPO/releases --paginate --jq '.[] | {tag_name,name,published_at,author:.author.login}'
gh api repos/OWNER/REPO/issues/comments --paginate
gh api repos/OWNER/REPO/pulls/comments --paginate
```

### Critical repository elements

Prioritize:

- Configuration: `.env`, `.env.example`, `config.*`, `settings.py`, `credentials.json`, `docker-compose.yml`
- CI/CD: `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, deploy scripts, release automation
- Dependencies: `package.json`, `requirements.txt`, `go.mod`, `pom.xml`, lockfiles
- Infrastructure: Terraform, Kubernetes manifests, Dockerfiles, cloud config, staging URLs
- Documentation: README, API docs, examples, diagrams, architecture notes, onboarding guides
- Data layer: migrations, seed data, schema files, sample dumps, connection strings
- Collaboration: issues, PR reviews, comments, discussions, wiki pages, commit messages

---

## 5. Advanced Code Search Patterns

Use GitHub search first, then fall back to search-engine dorks and `/secrets` for scanner-based validation.

### Scope operators

```text
user:USERNAME SEARCH_TERM
org:ORG SEARCH_TERM
repo:OWNER/REPO SEARCH_TERM
"target.com" org:ORG
```

### File and path filters

```text
extension:env "DATABASE_URL"
extension:json "password"
extension:yml "secret"
extension:pem "PRIVATE KEY"
filename:.env.example
filename:credentials.json
filename:docker-compose.yml
filename:travis.yml
path:.github/workflows
path:src/config
path:database
```

### Sensitive data indicators

```text
"api_key" OR "apikey" OR "api-key"
"secret" OR "password" OR "token" OR "auth"
"aws_access_key" OR "aws_secret" OR "AWS_SECRET_ACCESS_KEY"
"ghp_" OR "github_pat_" OR "xoxb-" OR "sk-"
"DATABASE_URL" OR "DB_PASSWORD" OR "MONGODB_URI" OR "REDIS_URL"
"GOOGLE_CLIENT_SECRET" OR "FACEBOOK_APP_SECRET" OR "TWITTER_API_KEY"
"herokuapp.com" OR "firebaseio.com"
"192.168." OR "10." OR "172.16." OR "localhost" OR "staging" OR "internal"
```

### CLI examples

```bash
gh search code '"target.com" filename:.env' --owner=ORG
gh search code '"DATABASE_URL" OR "DB_PASSWORD"' --repo=OWNER/REPO
gh search code '"AWS_SECRET_ACCESS_KEY"' --owner=ORG
```

**Validation:** treat code-search hits as leads. Run `/secrets` with TruffleHog/Gitleaks for credential classification, and never test or use credentials unless explicitly authorized in a defensive engagement.

---

## 6. Metadata and Historical Analysis

### Commit emails and attribution

```bash
gh api repos/OWNER/REPO/commits --paginate --jq '.[] | {sha:.sha, date:.commit.author.date, name:.commit.author.name, email:.commit.author.email, login:.author.login, message:.commit.message}'
```

Analyze:

- Author emails and domains → pivot to `/email-deep`, `/breach-deep`, `/email-permute`
- Commit timestamp patterns → working hours, time zones, release crunches, project maturity
- Message content → internal ticket IDs, project names, incident references, customer/org names
- Ownership areas → files most touched by each contributor
- Review/merge patterns → project workflow and approval structure

### Branch, fork, and release analysis

```bash
gh api repos/OWNER/REPO/forks --paginate --jq '.[] | {full_name,owner:.owner.login,created_at,updated_at,stargazers_count}'
gh api repos/OWNER/REPO/branches --paginate --jq '.[].name'
gh api repos/OWNER/REPO/tags --paginate --jq '.[].name'
```

Use forks to identify unofficial mirrors, code reuse, backups, internal copies of external projects, and former employee or contractor activity. Use branches/tags/releases to infer development workflow, feature timelines, and release preparation patterns.

### Account creation date detection

Primary method:

```bash
curl -s "https://api.github.com/users/USERNAME" | jq -r '.created_at'
gh api users/USERNAME --jq '.created_at'
```

Batch method:

```bash
for user in USER1 USER2 USER3; do
  printf "%s: " "$user"
  curl -s "https://api.github.com/users/$user" | jq -r '.created_at'
  sleep 1
 done
```

Record account age as context only. New accounts are not inherently malicious; correlate with behavior, repos, links, and timing.

---

## 7. Automated Tool Cascade

| Priority | Tool | Use |
|----------|------|-----|
| Primary | GitHub CLI (`gh`) | API access, pagination, code/repo search, auth-aware rate limits |
| Primary | curl + jq | Universal unauthenticated profile/repo snapshots |
| Secret validation | TruffleHog | Verified credential detection across repos/orgs |
| Secret validation | Gitleaks | Pattern/entropy detection, including git history |
| Repo recon | GitRob | Organization repository analysis where already installed |
| Repo recon | GitRecon | User/org/repo reconnaissance where already installed |
| Email pivot | ghintel.secrets.ninja | Commit-email enrichment and attribution leads |
| Fallback | GitHub web search | Manual review when CLI/API is rate-limited |
| Fallback | Search-engine dorks | `site:github.com`, `gist.github.com`, Sourcegraph, archived pages |

If GitRob or GitRecon is unavailable, do not auto-install by default; continue with `gh`, curl + jq, TruffleHog, Gitleaks, and manual review, then log the collection gap.

---

## 8. Case Model Integration

Register these entities and links:

- GitHub user → `Username` subject; aliases include profile name, blog/social links, public email
- Organization → `Organization` subject; `owns` repos, `employs/linked_to` visible members when corroborated
- Repository → `Asset` subject; `owned_by` org/user, `forked_from` upstream, `uses` languages/frameworks
- Commit email → `Email` subject; link to GitHub user with confidence based on API attribution
- Domain/URL in code → `Domain` or `Asset` subject; feed to `/subdomain`, `/techstack`, `/threat-check`
- Secret finding → Finding with severity and responsible disclosure status; feed to `/secrets` validation

Confidence guidance:

| Evidence | Confidence |
|----------|------------|
| GitHub API profile/repo fields | HIGH |
| Commit author email with linked GitHub user | HIGH |
| Commit author email without linked user | MEDIUM |
| Public org member list | HIGH for membership visibility, MEDIUM for employment inference |
| Followers/following | LOW as relationship proof; use as lead only |
| Code search result | MEDIUM until file context and repo ownership are reviewed |
| Verified TruffleHog secret | CRITICAL severity, HIGH confidence |

---

## 9. Reporting Checklist

Include:

- Target scope: users, orgs, repos, domains, search terms, collection date/time
- Methods: API, `gh`, code search, secret scanners, web/manual review, rate-limit gaps
- Profile summary: account age, public repos/gists, location/company/bio links, follower/following counts
- Repository inventory: notable repos, languages, activity, forks, stars, licenses, archived status
- Exposure findings: secrets, internal URLs, CI/CD weaknesses, dependency/security signals
- Metadata findings: emails, timeline, working-hour patterns, ownership areas, collaboration graph
- Risk assessment: impact, likelihood, affected assets, recommended mitigation
- Responsible disclosure plan for live or likely-live credentials

---

*GitHub OSINT Module v1.0.0*
*Part of CTI Expert Skill — public-data reconnaissance only*
